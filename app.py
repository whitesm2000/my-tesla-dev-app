"""Minimal Tesla Fleet API OAuth + webhook sandbox."""
import logging
import os
import secrets
import time

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("tesla-dev-app")

app = FastAPI(title="my-tesla-dev-app")

TESLA_AUTH_URL = os.getenv("TESLA_AUTH_URL", "https://fleet-auth.prd.na.vn.cloud.tesla.com").rstrip("/")
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
STATE_TTL_SECONDS = 600


def _now() -> int:
    return int(time.time())


def _purge_expired_states() -> None:
    cutoff = _now() - STATE_TTL_SECONDS
    expired = [s for s, ts in STATE_STORE.items() if ts < cutoff]
    for s in expired:
        STATE_STORE.pop(s, None)


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
    log.info(
        "Tokens stored: type=%s expires_in=%s scope=%s has_refresh=%s",
        tokens.get("token_type"),
        tokens.get("expires_in"),
        tokens.get("scope"),
        bool(tokens.get("refresh_token")),
    )
    return JSONResponse(
        {
            "ok": True,
            "token_type": tokens.get("token_type"),
            "expires_in": tokens.get("expires_in"),
            "scope": tokens.get("scope"),
            "has_refresh_token": bool(tokens.get("refresh_token")),
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
    return {"keys": list(TOKENS.keys()), "tokens": out}


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


@app.post("/webhook/tesla")
async def webhook_tesla(request: Request):
    body = await request.body()
    log.info("Webhook received (%d bytes)", len(body))
    return JSONResponse({"received": True, "bytes": len(body)})


@app.get("/health")
def health():
    return {"ok": True}