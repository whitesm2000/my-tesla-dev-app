# my-tesla-dev-app

Personal sandbox for the Tesla Fleet API. Receives the OAuth callback and
Tesla webhooks so we can experiment with scopes, vehicle data, and alerts
against our own vehicle.

## Endpoints

- `GET /` — liveness + presence check for `TESLA_CLIENT_ID` / `TESLA_CLIENT_SECRET`.
- `GET /auth/tesla/callback` — receives Tesla's OAuth redirect (returns the `code` and `state` for now).
- `POST /webhook/tesla` — receives Tesla webhook deliveries.
- `GET /health` — Render health check.

## Environment variables (set in Render)

| Var | Purpose |
|---|---|
| `TESLA_CLIENT_ID` | Issued by Tesla after app approval. |
| `TESLA_CLIENT_SECRET` | Issued by Tesla after app approval. |
| `TESLA_REDIRECT_URI` | Must match the redirect URI registered with Tesla, e.g. `https://my-tesla-dev-app.onrender.com/auth/tesla/callback`. |

## Local dev

```
pip install -r requirements.txt
uvicorn app:app --reload --port 3000
```