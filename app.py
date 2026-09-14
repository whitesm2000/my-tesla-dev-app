"""Minimal Tesla Fleet API OAuth + webhook sandbox."""
import os
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("tesla-dev-app")

app = FastAPI(title="my-tesla-dev-app")


@app.get("/")
def root():
    return {
        "service": "my-tesla-dev-app",
        "status": "ok",
        "has_client_id": bool(os.getenv("TESLA_CLIENT_ID")),
        "has_client_secret": bool(os.getenv("TESLA_CLIENT_SECRET")),
    }


@app.get("/auth/tesla/callback")
async def auth_tesla_callback(request: Request):
    params = dict(request.query_params)
    log.info("OAuth callback received: code=%s state=%s", params.get("code"), params.get("state"))
    return JSONResponse({
        "received": True,
        "code": params.get("code"),
        "state": params.get("state"),
        "error": params.get("error"),
    })


@app.post("/webhook/tesla")
async def webhook_tesla(request: Request):
    body = await request.body()
    log.info("Webhook received (%d bytes)", len(body))
    return JSONResponse({"received": True, "bytes": len(body)})


@app.get("/health")
def health():
    return {"ok": True}