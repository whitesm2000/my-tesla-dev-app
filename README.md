# my-tesla-dev-app

Personal sandbox for the [Tesla Fleet API](https://developer.tesla.com/docs/fleet-api).
FastAPI service on Render, OAuth-protected, talks to Tesla's Fleet API to read live
state from your own vehicles and (for older vehicles) send commands.

- **Live URL:** https://tesla.clintonbracesmd.com
- **Repo:** https://github.com/whitesm2000/my-tesla-dev-app
- **Tesla app (sandbox):** "My Tesla Dev App" (client_id `7682f941-6322-43ab-a8ce-2b6e64f60ee4`)

---

## What it does

- **OAuth Authorization Code + Refresh Token flow** with Tesla (`auth.tesla.com`)
- **Partner account registration** with Tesla (`fleet-api.prd.na.vn.cloud.tesla.com`)
- **Token persistence** to Render disk (`/var/data/tesla_tokens.json`)
- **Auto-refresh** of the access token via the refresh token (within 5 min of expiry)
- **EC secp256r1 keypair** generated on first run, persisted to disk, public key served at the Tesla-required `/.well-known/appspecific/com.tesla.3p.public-key.pem` path
- **Read-only Fleet API endpoints**: list vehicles, charge, climate, location, mobile_enabled, service_data, nearby_charging, release_notes, fleet_status, wake_up
- **Command endpoints** (unsigned, work for older Model X firmware): flash_lights, honk_horn, lock, unlock, charge_start/stop, climate_on/off, set_charge_limit, set_temps, charge_port_open/close

Every command requires `?confirm=true` to execute.

---

## Live data examples

```bash
# List vehicles
curl https://tesla.clintonbracesmd.com/api/vehicles

# Battery / range on a specific car
curl https://tesla.clintonbracesmd.com/api/vehicle/<vehicle_id>/charge

# Wake a sleeping car
curl -X POST https://tesla.clintonbracesmd.com/api/vehicle/<vehicle_id>/wake_up

# Flash the headlights
curl -X POST "https://tesla.clintonbracesmd.com/api/vehicle/<vehicle_id>/flash_lights?confirm=true"
```

Replace `<vehicle_id>` with a vehicle's `id` field from `/api/vehicles`.

---

## Endpoints

### OAuth

| Method | Path | Purpose |
|---|---|---|
| GET | `/login` | Redirects to Tesla's OAuth consent screen |
| GET | `/auth/tesla/callback` | Tesla redirects here after consent. Exchanges code for tokens, persists to disk. |

### Setup

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/register` | One-time: register this app as a Tesla partner account. Requires valid `client_credentials` partner token. |

### Vehicles (read)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/vehicles` | List all vehicles |
| GET | `/api/vehicle/{vin_or_id}` | Vehicle metadata |
| GET | `/api/vehicle/{vin_or_id}/data` | Live data (configure `?endpoints=charge_state;drive_state;...`) |
| GET | `/api/vehicle/{vin_or_id}/charge` | Battery, range, charging state |
| GET | `/api/vehicle/{vin_or_id}/climate` | Cabin / outside temps |
| GET | `/api/vehicle/{vin_or_id}/location` | Last-known GPS coords |
| GET | `/api/vehicle/{vin_or_id}/mobile_enabled` | Mobile API enabled? |
| GET | `/api/vehicle/{vin_or_id}/service_data` | Service status |
| GET | `/api/vehicle/{vin_or_id}/nearby_charging` | Nearby Superchargers |
| GET | `/api/vehicle/{vin_or_id}/release_notes` | Firmware release notes |
| POST | `/api/vehicle/{vin_or_id}/fleet_status` | Firmware version + virtual key info |
| POST | `/api/vehicle/{vin_or_id}/wake_up` | Wake the car from sleep |

### Vehicles (commands, require `?confirm=true`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/vehicle/{vin_or_id}/flash_lights` | Flash headlights |
| POST | `/api/vehicle/{vin_or_id}/honk_horn` | Honk horn |
| POST | `/api/vehicle/{vin_or_id}/lock` | Lock doors |
| POST | `/api/vehicle/{vin_or_id}/unlock` | Unlock doors |
| POST | `/api/vehicle/{vin_or_id}/charge_start` | Start charging |
| POST | `/api/vehicle/{vin_or_id}/charge_stop` | Stop charging |
| POST | `/api/vehicle/{vin_or_id}/charge_port_open` | Open charge port |
| POST | `/api/vehicle/{vin_or_id}/charge_port_close` | Close charge port |
| POST | `/api/vehicle/{vin_or_id}/climate_on` | Start climate |
| POST | `/api/vehicle/{vin_or_id}/climate_off` | Stop climate |
| POST | `/api/vehicle/{vin_or_id}/set_charge_limit?percent=N` | Set charge limit (50-100) |
| POST | `/api/vehicle/{vin_or_id}/set_temps?driver=N&passenger=N` | Set cabin temps (°C) |

### Webhook + utilities

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/appspecific/com.tesla.3p.public-key.pem` | Tesla-required public key |
| POST | `/webhook/tesla` | Webhook receiver (signature verification stubbed) |
| GET | `/debug/tokens` | Token metadata |
| GET | `/debug/persistence` | Disk status |
| GET | `/health` | Liveness |

---

## Architecture

```
Browser ── /login ──► FastAPI ── 307 ──► auth.tesla.com/oauth2/v3/authorize
                                                     │
                                                     ▼ (consent)
Browser ◄── /auth/tesla/callback ◄── auth.tesla.com
                          │
                          ▼
                   POST /oauth2/v3/token  (code → access + refresh)
                          │
                          ▼
                   /var/data/tesla_tokens.json (persisted)
                          │
                          ▼
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
/api/vehicles      /api/register    /api/vehicle/<id>/...
GET /api/1/        POST /api/1/      GET/POST /api/1/...
vehicles           partner_accounts vehicles/...
        │                 │                 │
        └──────────► Bearer access_token ◄──┘
                          │
                          ▼
                  (refresh_token rotates every 8h, transparent)
```

---

## Setup (how this was built)

### 1. Tesla Developer App
- Created at https://developer.tesla.com/en_US/request
- OAuth Grant Type: **Authorization Code and Machine-to-Machine** (both)
- All 7 scopes enabled: `vehicle_device_data`, `vehicle_cmds`, `vehicle_charging_cmds`, `vehicle_location`, `vehicle_basic_data`, `energy_device_data`, `energy_cmds`
- Initial allowed_origin: `https://my-tesla-dev-app.onrender.com`
- Later updated to: `https://tesla.clintonbracesmd.com`
- Client credentials captured at app creation.

### 2. Render Web Service
- Created via `render_create_web_service` (starter plan, Ohio region)
- Build: `pip install -r requirements.txt`
- Start: `uvicorn app:app --host 0.0.0.0 --port $PORT`
- Attached a 1 GB disk at `/var/data` for token + keypair persistence
- Env vars: `TESLA_CLIENT_ID`, `TESLA_CLIENT_SECRET`, `TESLA_AUTH_URL=https://auth.tesla.com`, `TESLA_BASE_URL=https://fleet-api.prd.na.vn.cloud.tesla.com`, `TESLA_REDIRECT_URI=https://tesla.clintonbracesmd.com/auth/tesla/callback`

### 3. Custom Domain via Cloudflare + Render
- Added DNS CNAME: `tesla.clintonbracesmd.com` → `my-tesla-dev-app.onrender.com` (DNS only)
- Added `tesla.clintonbracesmd.com` as a custom domain on Render (Let's Encrypt cert auto-issued)

### 4. Partner Account Registration
- Tesla requires `https://<root_domain>/.well-known/appspecific/com.tesla.3p.public-key.pem` to be served for partner registration
- Since `clintonbracesmd.com` (apex) already CNAMEs to `clintonbraces-website.onrender.com` (the orthodontist site), we added the public key file to the static site at `public/.well-known/appspecific/com.tesla.3p.public-key.pem` (via GitHub Contents API)
- Tesla's `/api/1/partner_accounts` endpoint accepted `domain=tesla.clintonbracesmd.com` (the full subdomain) as the registration domain

### 5. OAuth Flow
- Visit `/login`, log in to Tesla, grant consent → callback → tokens persisted to disk
- Tokens auto-refresh every 8 hours using the refresh_token

---

## Environment Variables

| Var | Default | Purpose |
|---|---|---|
| `TESLA_AUTH_URL` | `https://auth.tesla.com` | OAuth token + authorize endpoint |
| `TESLA_BASE_URL` | `https://fleet-api.prd.na.vn.cloud.tesla.com` | Fleet API base |
| `TESLA_CLIENT_ID` | _(required)_ | From Tesla Developer dashboard |
| `TESLA_CLIENT_SECRET` | _(required)_ | From Tesla Developer dashboard |
| `TESLA_REDIRECT_URI` | _(required)_ | Must match the allowed_redirect_uri in Tesla dashboard |
| `TOKEN_STORE_PATH` | `/var/data/tesla_tokens.json` | Where tokens are persisted |
| `PRIVATE_KEY_PATH` | `/var/data/tesla_private_key.pem` | EC private key (Tesla command signing) |
| `PUBLIC_KEY_PATH` | `/var/data/tesla_public_key.pem` | EC public key |

---

## Known limitations / TODO

- **Signed commands: DONE.** `tesla-http-proxy` (Tesla's official Go signer) is built during each deploy and runs alongside the API on `127.0.0.1:8081` (HTTPS, self-signed cert), sharing the `/var/data` disk so it signs with the registered private key. Commands auto-fall back to the proxy when Tesla replies "Command Protocol required". Verified working on Model 3 (2020) and Cybertruck (2024) after virtual-key pairing via `https://tesla.com/_ak/<domain>?vin=<VIN>` links (note: the asterisks in Tesla's docs are placeholder markup — do not include them).
- **Webhooks**: `/webhook/tesla` is a stub. Need to:
  - Verify Tesla's signature header (uses the registered EC public key)
  - Implement `fleet_telemetry_config` registration so Tesla pushes events
- **Location**: Tesla requires the `vehicle_location` scope and a `location_data` endpoint query to share GPS. Coordinates are returned in `drive_state` when available.
- **Refresh token rotation**: We persist `refresh_token` but don't proactively rotate it. If Tesla issues a new refresh_token, we save it.
- **Energy endpoints**: Scopes are enabled but no endpoints implemented yet.

---

## Local development

```bash
git clone https://github.com/whitesm2000/my-tesla-dev-app
cd my-tesla-dev-app
pip install -r requirements.txt
# Create .env or export:
export TESLA_CLIENT_ID=...
export TESLA_CLIENT_SECRET=...
export TESLA_REDIRECT_URI=http://localhost:3000/auth/tesla/callback
# Use a different disk path for local dev:
export TOKEN_STORE_PATH=/tmp/tesla_tokens.json
export PRIVATE_KEY_PATH=/tmp/tesla_private_key.pem
export PUBLIC_KEY_PATH=/tmp/tesla_public_key.pem

uvicorn app:app --reload --port 3000
```


## Send a navigation destination

Install the versioned CLI with `install -m 755 cli/tesla ~/.local/bin/tesla`.

```bash
tesla navigate cybertruck "123 Main St, Washington, DC" --yes
```

Use a full address or unambiguous place name in quotes. This shares the text
with the car's navigation system; it does not drive the vehicle. No automatic
wake or retry is performed. If Tesla reports the car asleep, wake it explicitly
and retry. A successful response means Tesla accepted the command; verify the
resolved destination on the car's screen before using the route.

API: `POST /api/vehicle/{id}/navigate?confirm=true` with JSON
`{"destination":"123 Main St, Washington, DC"}` and the existing bearer token.
Empty, whitespace-only, non-string and overlong destinations are rejected.
This uses Tesla's `navigation_request` REST command and existing command routing.

Tests (mocked Tesla traffic, no vehicle commands):
`python -m unittest discover -s tests -v`.
