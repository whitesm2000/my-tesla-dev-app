"""Minimal Tesla Fleet API OAuth + webhook sandbox."""
import json
import logging
import os
import secrets
import time

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("tesla-dev-app")

app = FastAPI(title="my-tesla-dev-app")

TESLA_AUTH_URL = os.getenv("TESLA_AUTH_URL", "https://auth.tesla.com").rstrip("/")
TESLA_API_URL = os.getenv("TESLA_BASE_URL", "https://fleet-api.prd.na.vn.cloud.tesla.com").rstrip("/")
TESLA_CLIENT_ID = os.getenv("TESLA_CLIENT_ID", "")
TESLA_CLIENT_SECRET = os.getenv("TESLA_CLIENT_SECRET", "")
TESLA_REDIRECT_URI = os.getenv("TESLA_REDIRECT_URI", "")

DEFAULT_SCOPES = (
    "openid email offline_access "
    "vehicle_device_data vehicle_cmds vehicle_charging_cmds "
    "vehicle_location vehicle_basic_data "
    "energy_device_data energy_cmds"
)

TOKENS: dict = {}
STATE_STORE: dict = {}
PARTNER_TOKEN: dict = {}
STATE_TTL_SECONDS = 600

TOKEN_STORE_PATH = os.getenv("TOKEN_STORE_PATH", "/var/data/tesla_tokens.json")
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "/var/data/tesla_private_key.pem")
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY_PATH", "/var/data/tesla_public_key.pem")
WELL_KNOWN_PUBLIC_KEY_PATH = "/.well-known/appspecific/com.tesla.3p.public-key.pem"
PROXY_URL = os.getenv("TESLA_PROXY_URL", "http://127.0.0.1:8081")

_VIN_CACHE: dict = {}


async def _id_to_vin(vehicle_id: str) -> str:
    """Map a numeric vehicle id to its VIN (proxy endpoints key on VIN)."""
    if vehicle_id in _VIN_CACHE:
        return _VIN_CACHE[vehicle_id]
    token = await _user_token()
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{TESLA_API_URL}/api/1/vehicles",
            headers={"Authorization": f"Bearer {token}"},
        )
    if resp.status_code == 200:
        for v in resp.json().get("response", []):
            _VIN_CACHE[str(v["id"])] = v["vin"]
    return _VIN_CACHE.get(vehicle_id, vehicle_id)


def _now() -> int:
    return int(time.time())


def _purge_expired_states() -> None:
    cutoff = _now() - STATE_TTL_SECONDS
    expired = [s for s, ts in STATE_STORE.items() if ts < cutoff]
    for s in expired:
        STATE_STORE.pop(s, None)


def _load_tokens() -> None:
    global TOKENS
    try:
        with open(TOKEN_STORE_PATH, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            TOKENS = data
            log.info("Loaded %d token entries from %s", len(TOKENS), TOKEN_STORE_PATH)
    except FileNotFoundError:
        log.info("No token store found at %s (fresh start)", TOKEN_STORE_PATH)
    except Exception as exc:
        log.warning("Failed to load tokens from %s: %s", TOKEN_STORE_PATH, exc)


def _save_tokens() -> bool:
    try:
        os.makedirs(os.path.dirname(TOKEN_STORE_PATH), exist_ok=True)
        with open(TOKEN_STORE_PATH, "w") as f:
            json.dump(TOKENS, f, indent=2)
        return True
    except Exception as exc:
        log.warning("Failed to save tokens to %s: %s", TOKEN_STORE_PATH, exc)
        return False


def _load_or_generate_keypair() -> None:
    os.makedirs(os.path.dirname(PRIVATE_KEY_PATH), exist_ok=True)
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        log.info("Using existing keypair at %s", PRIVATE_KEY_PATH)
        return
    log.info("Generating new EC secp256r1 keypair")
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_pem)
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)
    log.info("Saved keypair to %s and %s", PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)


_load_tokens()
_load_or_generate_keypair()

API_TOKEN = os.getenv("TESLA_API_TOKEN", "")
PUBLIC_PATHS = ("/login", "/auth/tesla/callback", "/.well-known/", "/health", "/webhook/")


@app.middleware("http")
async def require_api_token(request: Request, call_next):
    """Bearer-token gate for everything except the OAuth redirect flow,
    the Tesla-required public key, health checks, and inbound webhooks."""
    if API_TOKEN and not any(request.url.path.startswith(p) for p in PUBLIC_PATHS):
        auth = request.headers.get("authorization", "")
        if auth != f"Bearer {API_TOKEN}":
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)



@app.get("/")
def root():
    return {
        "service": "my-tesla-dev-app",
        "status": "ok",
        "has_client_id": bool(TESLA_CLIENT_ID),
        "has_client_secret": bool(TESLA_CLIENT_SECRET),
        "redirect_uri": TESLA_REDIRECT_URI,
        "tesla_auth_url": TESLA_AUTH_URL,
        "tesla_api_url": TESLA_API_URL,
        "scopes": DEFAULT_SCOPES,
    }


@app.get("/login")
def login():
    if not TESLA_CLIENT_ID or not TESLA_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="missing TESLA_CLIENT_ID or TESLA_REDIRECT_URI")
    _purge_expired_states()
    state = secrets.token_urlsafe(24)
    STATE_STORE[state] = _now()
    scopes = "+".join(DEFAULT_SCOPES.split())
    auth_url = (
        f"{TESLA_AUTH_URL}/oauth2/v3/authorize"
        f"?response_type=code"
        f"&client_id={TESLA_CLIENT_ID}"
        f"&redirect_uri={TESLA_REDIRECT_URI}"
        f"&scope={scopes}"
        f"&state={state}"
    )
    log.info("Redirecting to Tesla auth (state=%s...)", state[:8])
    return RedirectResponse(auth_url)


@app.get("/auth/tesla/callback")
async def auth_tesla_callback(request: Request):
    params = dict(request.query_params)
    code = params.get("code")
    state = params.get("state")
    error = params.get("error")

    if error:
        log.warning("OAuth error from Tesla: %s", params.get("error_description") or error)
        return JSONResponse(
            {"error": error, "description": params.get("error_description")},
            status_code=400,
        )
    if not code or not state:
        raise HTTPException(status_code=400, detail="missing code or state")

    issued_at = STATE_STORE.pop(state, None)
    if issued_at is None:
        raise HTTPException(status_code=400, detail="invalid state (not found or already used)")
    if _now() - issued_at > STATE_TTL_SECONDS:
        raise HTTPException(status_code=400, detail="expired state")

    token_url = f"{TESLA_AUTH_URL}/oauth2/v3/token"
    log.info("Exchanging code for tokens at %s", token_url)
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": TESLA_CLIENT_ID,
                "client_secret": TESLA_CLIENT_SECRET,
                "code": code,
                "redirect_uri": TESLA_REDIRECT_URI,
                "audience": TESLA_API_URL,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if resp.status_code != 200:
        log.error("Token exchange failed (%s): %s", resp.status_code, resp.text[:500])
        return JSONResponse(
            {"error": "token_exchange_failed", "status": resp.status_code, "body": resp.text},
            status_code=resp.status_code,
        )

    tokens = resp.json()
    tokens["_obtained_at"] = _now()
    TOKENS["default"] = tokens
    saved = _save_tokens()
    log.info(
        "Tokens stored: type=%s expires_in=%s scope=%s has_refresh=%s persisted=%s",
        tokens.get("token_type"),
        tokens.get("expires_in"),
        tokens.get("scope"),
        bool(tokens.get("refresh_token")),
        saved,
    )
    return JSONResponse(
        {
            "ok": True,
            "token_type": tokens.get("token_type"),
            "expires_in": tokens.get("expires_in"),
            "scope": tokens.get("scope"),
            "has_refresh_token": bool(tokens.get("refresh_token")),
            "persisted": saved,
            "store_path": TOKEN_STORE_PATH,
        }
    )


@app.get("/debug/tokens")
def debug_tokens():
    out = {}
    for k, v in TOKENS.items():
        obtained_at = v.get("_obtained_at", 0)
        expires_in = v.get("expires_in", 0)
        out[k] = {
            "token_type": v.get("token_type"),
            "expires_at_epoch": obtained_at + expires_in,
            "scope": v.get("scope"),
            "has_refresh_token": bool(v.get("refresh_token")),
        }
    return {"keys": list(TOKENS.keys()), "tokens": out, "store_path": TOKEN_STORE_PATH}


@app.get("/debug/persistence")
def debug_persistence():
    """Check whether the configured TOKEN_STORE_PATH is writable + readable."""
    import tempfile

    info = {
        "store_path": TOKEN_STORE_PATH,
        "store_dir_exists": os.path.isdir(os.path.dirname(TOKEN_STORE_PATH)),
        "store_writable": False,
        "store_readable": False,
        "tokens_loaded": len(TOKENS),
    }
    try:
        os.makedirs(os.path.dirname(TOKEN_STORE_PATH), exist_ok=True)
        with open(TOKEN_STORE_PATH, "a") as f:
            pass
        info["store_writable"] = os.access(TOKEN_STORE_PATH, os.W_OK)
        info["store_readable"] = os.access(TOKEN_STORE_PATH, os.R_OK)
    except Exception as exc:
        info["error"] = str(exc)
    info["tmp_writable"] = tempfile.mkstemp()[1] != ""
    return info


@app.get("/api/vehicles")
async def list_vehicles():
    token_data = TOKENS.get("default")
    if not token_data:
        raise HTTPException(status_code=401, detail="no tokens stored; visit /login first")
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=500, detail="stored token has no access_token field")

    url = f"{TESLA_API_URL}/api/1/vehicles"
    log.info("Calling Tesla Fleet API: GET %s", url)
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if resp.status_code != 200:
        log.error("Tesla API error (%s): %s", resp.status_code, resp.text[:500])
        return JSONResponse(
            {
                "error": "tesla_api_error",
                "status": resp.status_code,
                "body": resp.text[:1000],
            },
            status_code=resp.status_code,
        )
    return JSONResponse(resp.json())


async def _user_token() -> str:
    token_data = TOKENS.get("default")
    if not token_data:
        raise HTTPException(status_code=401, detail="no tokens stored; visit /login first")
    obtained_at = token_data.get("_obtained_at", 0)
    expires_in = token_data.get("expires_in", 0)
    # Refresh 5 minutes before expiry
    if _now() >= obtained_at + expires_in - 300:
        log.info("Access token expired/expiring; refreshing")
        refresh_token = token_data.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=401, detail="access token expired and no refresh_token; visit /login again")
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{TESLA_AUTH_URL}/oauth2/v3/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": TESLA_CLIENT_ID,
                    "client_secret": TESLA_CLIENT_SECRET,
                    "refresh_token": refresh_token,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if resp.status_code != 200:
            log.error("Refresh failed (%s): %s", resp.status_code, resp.text[:300])
            raise HTTPException(
                status_code=resp.status_code,
                detail={"error": "refresh_failed", "body": resp.text[:500]},
            )
        new_tokens = resp.json()
        new_tokens["_obtained_at"] = _now()
        TOKENS["default"] = new_tokens
        _save_tokens()
        log.info("Refreshed access token, expires_in=%s", new_tokens.get("expires_in"))
        return new_tokens["access_token"]
    return token_data["access_token"]


async def _vehicle_get(path: str, vehicle_id: str | None = None) -> dict:
    token = await _user_token()
    url = f"{TESLA_API_URL}/api/1/vehicles"
    if vehicle_id:
        url = f"{url}/{vehicle_id}{path}"
    else:
        url = f"{url}{path}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code != 200:
        log.error("Tesla API GET %s -> %s: %s", url, resp.status_code, resp.text[:300])
        return {"error": "tesla_api_error", "status": resp.status_code, "body": resp.text[:1000]}
    return resp.json()


async def _vehicle_post(path: str, vehicle_id: str, body: dict | None = None) -> dict:
    token = await _user_token()
    url = f"{TESLA_API_URL}/api/1/vehicles/{vehicle_id}{path}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json=body or {},
        )
    if resp.status_code not in (200, 201, 202):
        log.error("Tesla API POST %s -> %s: %s", url, resp.status_code, resp.text[:300])
        return {"error": "tesla_api_error", "status": resp.status_code, "body": resp.text[:1000]}
    return resp.json() if resp.text else {"ok": True}


@app.get("/api/vehicle/{vehicle_id}")
async def vehicle_detail(vehicle_id: str):
    """One vehicle's metadata."""
    return JSONResponse(await _vehicle_get("", vehicle_id))


@app.get("/api/vehicle/{vehicle_id}/data")
async def vehicle_data(vehicle_id: str, endpoints: str = "charge_state;vehicle_state;drive_state;climate_state;location_data"):
    """Live vehicle data. Pass `endpoints` query param like `charge_state;drive_state` to choose fields."""
    token = await _user_token()
    url = f"{TESLA_API_URL}/api/1/vehicles/{vehicle_id}/vehicle_data"
    log.info("vehicle_data: %s", url)
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params={"endpoints": endpoints},
        )
    if resp.status_code != 200:
        log.error("vehicle_data %s -> %s: %s", url, resp.status_code, resp.text[:300])
        return JSONResponse(
            {"error": "tesla_api_error", "status": resp.status_code, "body": resp.text[:1000]},
            status_code=resp.status_code,
        )
    return JSONResponse(resp.json())


@app.get("/api/vehicle/{vehicle_id}/location")
async def vehicle_location(vehicle_id: str):
    """Vehicle's last-known GPS coordinates."""
    token = await _user_token()
    url = f"{TESLA_API_URL}/api/1/vehicles/{vehicle_id}/vehicle_data"
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params={"endpoints": "location_data"},
        )
    if resp.status_code != 200:
        return JSONResponse(
            {"error": "tesla_api_error", "status": resp.status_code, "body": resp.text[:1000]},
            status_code=resp.status_code,
        )
    loc = (resp.json() or {}).get("response", {}).get("location_data") or {}
    return JSONResponse(
        {
            "latitude": loc.get("latitude"),
            "longitude": loc.get("longitude"),
            "heading": loc.get("heading"),
            "timestamp": loc.get("timestamp"),
            "raw": loc,
        }
    )


@app.get("/api/vehicle/{vehicle_id}/charge")
async def vehicle_charge(vehicle_id: str):
    """Battery, range, charging state."""
    token = await _user_token()
    url = f"{TESLA_API_URL}/api/1/vehicles/{vehicle_id}/vehicle_data"
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params={"endpoints": "charge_state"},
        )
    if resp.status_code != 200:
        return JSONResponse(
            {"error": "tesla_api_error", "status": resp.status_code, "body": resp.text[:1000]},
            status_code=resp.status_code,
        )
    return JSONResponse((resp.json() or {}).get("response", {}).get("charge_state", {}))


@app.get("/api/vehicle/{vehicle_id}/climate")
async def vehicle_climate(vehicle_id: str):
    """Inside / outside temp, climate settings."""
    token = await _user_token()
    url = f"{TESLA_API_URL}/api/1/vehicles/{vehicle_id}/vehicle_data"
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params={"endpoints": "climate_state"},
        )
    if resp.status_code != 200:
        return JSONResponse(
            {"error": "tesla_api_error", "status": resp.status_code, "body": resp.text[:1000]},
            status_code=resp.status_code,
        )
    return JSONResponse((resp.json() or {}).get("response", {}).get("climate_state", {}))


@app.post("/api/vehicle/{vehicle_id}/wake_up")
async def vehicle_wake(vehicle_id: str):
    """Wake the car up. Cars sleep deeply; first API call after sleep needs this."""
    return JSONResponse(await _vehicle_post("/wake_up", vehicle_id))


@app.get("/api/vehicle/{vehicle_id}/mobile_enabled")
async def vehicle_mobile_enabled(vehicle_id: str):
    """Whether the vehicle's mobile API access is enabled."""
    return JSONResponse(await _vehicle_get("/mobile_enabled", vehicle_id))


@app.get("/api/vehicle/{vehicle_id}/service_data")
async def vehicle_service_data(vehicle_id: str):
    """Service status for the vehicle."""
    return JSONResponse(await _vehicle_get("/service_data", vehicle_id))


@app.get("/api/vehicle/{vehicle_id}/nearby_charging")
async def vehicle_nearby_charging(vehicle_id: str):
    """Charging sites near the vehicle's current location."""
    return JSONResponse(await _vehicle_get("/nearby_charging_sites", vehicle_id))


@app.get("/api/vehicle/{vehicle_id}/release_notes")
async def vehicle_release_notes(vehicle_id: str):
    """Firmware release notes for the vehicle."""
    return JSONResponse(await _vehicle_get("/release_notes", vehicle_id))


@app.post("/api/vehicle/{vehicle_id}/fleet_status")
async def vehicle_fleet_status(vehicle_id: str):
    """Fleet status: firmware version, telemetry support, virtual key info."""
    return JSONResponse(await _vehicle_post("/fleet_status", vehicle_id, {"vin": vehicle_id}))


# ---- Commands ----
# Each command requires ?confirm=true to execute (safety).
# Note: newer vehicles / firmware require commands to be signed with the
# Tesla Vehicle Command Protocol. We forward to Tesla's signed_command /
# command/* endpoints; if Tesla rejects for signing, the response will say so.

def _require_confirm(confirm: str | None, command_name: str):
    if confirm != "true":
        raise HTTPException(
            status_code=400,
            detail=f"command '{command_name}' requires ?confirm=true to execute (safety)",
        )


async def _vehicle_command(vehicle_id: str, command: str, body: dict | None = None) -> dict:
    """Forward a command to Tesla. Returns raw response or error dict.

    Newer vehicles reject unsigned commands ("Tesla Vehicle Command Protocol
    required"). When that happens, retry through the local tesla-http-proxy,
    which signs the command with the app's virtual key private key."""
    token = await _user_token()
    url = f"{TESLA_API_URL}/api/1/vehicles/{vehicle_id}/command/{command}"
    log.info("command %s on %s body=%s", command, vehicle_id, body)
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json=body or {},
        )
    if resp.status_code == 403 and "Command Protocol required" in resp.text:
        log.info("vehicle %s requires signed commands; retrying via proxy", vehicle_id)
        return await _proxy_command(vehicle_id, command, token, body)
    if resp.status_code not in (200, 201, 202):
        log.error("command %s -> %s: %s", command, resp.status_code, resp.text[:400])
        return {"error": "tesla_api_error", "status": resp.status_code, "body": resp.text[:1500]}
    return resp.json() if resp.text else {"ok": True}


async def _proxy_command(vehicle_id: str, command: str, token: str, body: dict | None = None) -> dict:
    """Send a command through the local tesla-http-proxy (signed)."""
    vin = await _id_to_vin(vehicle_id)
    url = f"{PROXY_URL}/api/1/vehicles/{vin}/command/{command}"
    log.info("proxy command %s on vin %s", command, vin)
    try:
        async with httpx.AsyncClient(timeout=90, verify=False) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json=body or {},
            )
    except httpx.ConnectError:
        return {"error": "proxy_unavailable", "detail": f"cannot reach command proxy at {PROXY_URL}; is tesla-http-proxy running?"}
    try:
        data = resp.json() if resp.text else {"ok": True}
    except ValueError:
        data = {"raw": resp.text[:1000]}
    data["_via"] = "signed_proxy"
    data["_proxy_status"] = resp.status_code
    return data


class NavigationDestination(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    destination: str = Field(min_length=1, max_length=2000)


@app.post("/api/vehicle/{vehicle_id}/navigate")
async def cmd_navigate(vehicle_id: str, destination: NavigationDestination, confirm: str | None = None):
    """Share an address or place with the vehicle's navigation system."""
    _require_confirm(confirm, "navigate")
    body = {
        "type": "share_ext_content_raw",
        "value": {"android.intent.extra.TEXT": destination.destination},
        "locale": "en-US",
        "timestamp_ms": int(time.time() * 1000),
    }
    # Tesla resolves shared text server-side; the official proxy also routes
    # navigation_request through the REST API (ErrCommandUseRESTAPI).
    return JSONResponse(await _vehicle_command(vehicle_id, "navigation_request", body))


@app.post("/api/vehicle/{vehicle_id}/flash_lights")
async def cmd_flash_lights(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "flash_lights")
    return JSONResponse(await _vehicle_command(vehicle_id, "flash_lights"))


@app.post("/api/vehicle/{vehicle_id}/honk_horn")
async def cmd_honk_horn(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "honk_horn")
    return JSONResponse(await _vehicle_command(vehicle_id, "honk_horn"))


@app.post("/api/vehicle/{vehicle_id}/lock")
async def cmd_lock(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "lock")
    return JSONResponse(await _vehicle_command(vehicle_id, "door_lock"))


@app.post("/api/vehicle/{vehicle_id}/unlock")
async def cmd_unlock(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "unlock")
    return JSONResponse(await _vehicle_command(vehicle_id, "door_unlock"))


@app.post("/api/vehicle/{vehicle_id}/charge_start")
async def cmd_charge_start(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "charge_start")
    return JSONResponse(await _vehicle_command(vehicle_id, "charge_start"))


@app.post("/api/vehicle/{vehicle_id}/charge_stop")
async def cmd_charge_stop(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "charge_stop")
    return JSONResponse(await _vehicle_command(vehicle_id, "charge_stop"))


@app.post("/api/vehicle/{vehicle_id}/charge_port_open")
async def cmd_charge_port_open(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "charge_port_open")
    return JSONResponse(await _vehicle_command(vehicle_id, "charge_port_door_open"))


@app.post("/api/vehicle/{vehicle_id}/charge_port_close")
async def cmd_charge_port_close(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "charge_port_close")
    return JSONResponse(await _vehicle_command(vehicle_id, "charge_port_door_close"))


@app.post("/api/vehicle/{vehicle_id}/climate_on")
async def cmd_climate_on(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "climate_on")
    return JSONResponse(await _vehicle_command(vehicle_id, "auto_conditioning_start"))


@app.post("/api/vehicle/{vehicle_id}/climate_off")
async def cmd_climate_off(vehicle_id: str, confirm: str | None = None):
    _require_confirm(confirm, "climate_off")
    return JSONResponse(await _vehicle_command(vehicle_id, "auto_conditioning_stop"))


@app.post("/api/vehicle/{vehicle_id}/set_charge_limit")
async def cmd_set_charge_limit(vehicle_id: str, percent: int, confirm: str | None = None):
    _require_confirm(confirm, "set_charge_limit")
    if not 50 <= percent <= 100:
        raise HTTPException(status_code=400, detail="percent must be between 50 and 100")
    return JSONResponse(await _vehicle_command(vehicle_id, "set_charge_limit", {"percent": percent}))


@app.post("/api/vehicle/{vehicle_id}/set_temps")
async def cmd_set_temps(vehicle_id: str, driver: float, passenger: float | None = None, confirm: str | None = None):
    _require_confirm(confirm, "set_temps")
    body = {"driver_temp": driver}
    if passenger is not None:
        body["passenger_temp"] = passenger
    return JSONResponse(await _vehicle_command(vehicle_id, "set_temps", body))


@app.get(WELL_KNOWN_PUBLIC_KEY_PATH)
def serve_tesla_public_key():
    if not os.path.exists(PUBLIC_KEY_PATH):
        raise HTTPException(status_code=500, detail="public key not generated yet")
    return FileResponse(
        PUBLIC_KEY_PATH,
        media_type="application/x-pem-file",
        headers={"Cache-Control": "public, max-age=3600"},
    )


async def _mint_partner_token() -> dict:
    global PARTNER_TOKEN
    if PARTNER_TOKEN.get("_expires_at", 0) > _now() + 60:
        return PARTNER_TOKEN
    log.info("Minting partner token via client_credentials")
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{TESLA_AUTH_URL}/oauth2/v3/token",
            data={
                "grant_type": "client_credentials",
                "client_id": TESLA_CLIENT_ID,
                "client_secret": TESLA_CLIENT_SECRET,
                "scope": "openid email offline_access",
                "audience": TESLA_API_URL,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code,
            detail={"error": "partner_token_failed", "body": resp.text[:500]},
        )
    tok = resp.json()
    tok["_expires_at"] = _now() + int(tok.get("expires_in", 3600))
    PARTNER_TOKEN = tok
    log.info("Partner token minted, expires_at=%s", tok["_expires_at"])
    return tok


@app.post("/api/register")
async def register_partner():
    """Register this app as a partner account with the Tesla region.
    Required once per developer account per region before /api/1/* endpoints work."""
    if not TESLA_CLIENT_ID or not TESLA_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="missing client credentials")

    domain = TESLA_REDIRECT_URI.split("//", 1)[-1].split("/", 1)[0]
    public_key_pem = open(PUBLIC_KEY_PATH, "rb").read().decode()

    tok = await _mint_partner_token()
    url = f"{TESLA_API_URL}/api/1/partner_accounts"
    log.info("Registering partner account (domain=%s)", domain)
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            url,
            headers={"Authorization": f"Bearer {tok['access_token']}"},
            json={"domain": domain, "public_key": public_key_pem},
        )
    return JSONResponse(
        {
            "status": resp.status_code,
            "body": resp.text[:2000],
            "registered_domain": domain,
        },
        status_code=resp.status_code if resp.status_code < 400 else 502,
    )


@app.post("/webhook/tesla")
async def webhook_tesla(request: Request):
    body = await request.body()
    log.info("Webhook received (%d bytes)", len(body))
    return JSONResponse({"received": True, "bytes": len(body)})


@app.get("/debug/proxy")
async def debug_proxy():
    """Is the local tesla-http-proxy alive?"""
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            resp = await client.get(PROXY_URL)
        return {"proxy_url": PROXY_URL, "alive": True, "status": resp.status_code}
    except httpx.ConnectError:
        return {"proxy_url": PROXY_URL, "alive": False}


@app.get("/enroll")
async def enroll_keys():
    """Page for pairing this app's virtual key with each vehicle.

    Uses Tesla's deep-link flow: https://tesla.com/_ak/*<domain>* opens the
    Tesla app and walks the owner through adding the key to a vehicle."""
    import base64
    import io

    import qrcode
    from fastapi.responses import HTMLResponse

    domain = TESLA_REDIRECT_URI.split("//", 1)[-1].split("/", 1)[0]
    vehicles = []
    token = await _user_token()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{TESLA_API_URL}/api/1/vehicles",
                headers={"Authorization": f"Bearer {token}"},
            )
        if resp.status_code == 200:
            vehicles = resp.json().get("response", [])
    except Exception as exc:
        log.warning("enroll: could not list vehicles: %s", exc)

    cards = []
    for v in vehicles:
        link = f"https://tesla.com/_ak/{domain}?vin={v['vin']}"
        img = qrcode.make(link)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        name = v.get("display_name") or v["vin"]
        state = v.get("state", "unknown")
        cards.append(
            f"<div class='card'><h2>{name}</h2>"
            f"<p class='vin'>{v['vin']} &middot; {state}</p>"
            f"<img src='data:image/png;base64,{qr_b64}' alt='QR for {name}'/>"
            f"<p><a href='{link}'>Open pairing link on this phone</a></p>"
            f"<p class='mono'>{link}</p></div>"
        )

    html = f"""<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Enroll app key</title><style>
body{{font-family:-apple-system,system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;background:#111;color:#eee}}
.card{{background:#1d1d1f;border:1px solid #333;border-radius:12px;padding:1.25rem;margin:1rem 0;text-align:center}}
img{{width:220px;height:220px;background:#fff;padding:8px;border-radius:8px}}
a{{color:#4da3ff}}
.vin{{color:#999;font-size:.9rem}}
.mono{{font-family:monospace;font-size:.7rem;color:#777;word-break:break-all}}
ol{{line-height:1.7}}
</style></head><body>
<h1>Pair this app with your vehicles</h1>
<p>Newer vehicles require a <b>virtual key</b> before accepting commands from this app.
Open each link below <b>on a phone that has the Tesla app installed and is signed in as the owner</b>:</p>
<ol>
<li>Tap a pairing link (or scan the QR with the phone's camera)</li>
<li>The Tesla app opens &mdash; confirm adding the key for that vehicle</li>
<li>Follow any in-car confirmation prompts (e.g. tap your key card)</li>
<li>Repeat for each vehicle that needs command access</li>
</ol>
{''.join(cards) if cards else '<p>Could not list vehicles &mdash; visit <a href="/login">/login</a> first.</p>'}
<p class='mono'>public key: https://{domain}{WELL_KNOWN_PUBLIC_KEY_PATH}</p>
</body></html>"""
    return HTMLResponse(html)


@app.get("/health")
def health():
    return {"ok": True}