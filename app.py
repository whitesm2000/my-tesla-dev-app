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
    root_domain = ".".join(domain.split(".")[-2:])
    public_key_pem = open(PUBLIC_KEY_PATH, "rb").read().decode()

    tok = await _mint_partner_token()
    url = f"{TESLA_API_URL}/api/1/partner_accounts"
    log.info("Registering partner account (domain=%s, root=%s)", domain, root_domain)
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            url,
            headers={"Authorization": f"Bearer {tok['access_token']}"},
            json={"domain": root_domain, "public_key": public_key_pem},
        )
    return JSONResponse(
        {
            "status": resp.status_code,
            "body": resp.text[:2000],
            "registered_domain": root_domain,
        },
        status_code=resp.status_code if resp.status_code < 400 else 502,
    )


@app.post("/webhook/tesla")
async def webhook_tesla(request: Request):
    body = await request.body()
    log.info("Webhook received (%d bytes)", len(body))
    return JSONResponse({"received": True, "bytes": len(body)})


@app.get("/health")
def health():
    return {"ok": True}