# AGENTS.md — my-tesla-dev-app

FastAPI service on Render that wraps the Tesla Fleet API for the family's
vehicles. This is the single source of truth for Tesla OAuth tokens, the
virtual-key signing proxy, and all vehicle reads/commands.

## Architecture

- **App:** FastAPI (`app.py`), deployed at https://tesla.clintonbracesmd.com
- **Render service:** `my-tesla-dev-app` (srv-dajm0d3m8hqs738qicog), Ohio, starter plan, 1 GB disk at `/var/data`
- **Signing:** `tesla-http-proxy` (Tesla's official Go binary) is built during
  each deploy (see Build Command) and runs on `127.0.0.1:8081` alongside
  uvicorn (see Start Command). It shares the disk, so it signs with the
  registered private key. Commands auto-fall back to it when Tesla replies
  "Command Protocol required".
- **Auth:** all endpoints require `Authorization: Bearer $TESLA_API_TOKEN`
  except `/login`, `/auth/tesla/callback`, `/.well-known/*`, `/health`,
  `/webhook/*` (inbound Tesla traffic).
- **Persistence:** `/var/data/tesla_tokens.json` (OAuth tokens, auto-refreshed),
  `/var/data/tesla_private_key.pem` (virtual key). Do not commit or move these.
- **Domain:** `tesla.clintonbracesmd.com` — CNAME in Cloudflare (DNS only),
  cert via Render. The public key is ALSO served from the apex domain via the
  `clintonbraces-website` repo (`public/.well-known/appspecific/com.tesla.3p.public-key.pem`)
  because Tesla's partner registration fetches it from the root domain.
- **Tesla app:** client_id `7682f941-6322-43ab-a8ce-2b6e64f60ee4`, all scopes,
  partner account registered with domain `tesla.clintonbracesmd.com`.

## Conventions

- Read endpoints: `GET /api/vehicle/{id}/{charge,climate,location,data,...}`
- Command endpoints: `POST /api/vehicle/{id}/{flash_lights,honk_horn,lock,...}`
  — all require `?confirm=true` (safety typo-guard; real auth is the bearer token).
- New vehicles do NOT accept commands until the virtual key is paired:
  open `https://tesla.com/_ak/tesla.clintonbracesmd.com?vin=<VIN>` on the
  owner's phone (Tesla app). NOTE: no asterisks — the `*domain*` in Tesla's
  docs is placeholder markup, not literal URL characters.
- Deploy = push to `main` (auto-deploy). Tokens/keys survive deploys (disk).

## The `tesla` CLI

`~/.local/bin/tesla` (on JP's Mac) wraps this API for humans and AI agents.
Config: `~/.config/tesla/config.json` (`base_url`, `token`). Reads need no
flags; commands require `--yes`. Cars: `cybertruck`, `model3`, `modelx`.

## Testing after changes

```bash
curl -sS -H "Authorization: Bearer $TOKEN" https://tesla.clintonbracesmd.com/health
tesla status
tesla flash model3 --yes   # signed-path check (only with user OK)
```
