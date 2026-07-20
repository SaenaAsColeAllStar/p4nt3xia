# Expose P4NT3XIA with Cloudflare Tunnel

Practical guide to put a **running** local stack (frontend `:3000`, API `:8000`) on a public HTTPS URL using [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) (`cloudflared`).

## Security warning (read first)

P4NT3XIA is a **pentest platform** (Deep Scan + Attack Mode + Frida + payload templates).

- Only expose it to **people you trust**. A public URL means anyone who finds it can launch scans if auth is off.
- Prefer **`P4NT3XIA_AUTH_ENABLED=true`** (+ strong `P4NT3XIA_JWT_SECRET` and bootstrap admin) before sharing a tunnel URL.
- Attack Mode / non-GET API Mode / template runs / Frida still require the `authorized` flag — that does **not** replace auth.
- Do not point tunnels at production attack tooling without additional access control (Cloudflare Access is recommended for named tunnels).
- Quick tunnels (`trycloudflare.com`) URLs are ephemeral and still publicly reachable while the process runs.

## How the app is wired

| Service | Local port | Role |
|---------|------------|------|
| Next.js frontend | `3000` | UI |
| FastAPI backend | `8000` | REST + WebSocket `/ws/scans/{id}` |

The browser calls the API using:

- `NEXT_PUBLIC_API_URL` (default `http://localhost:8000`)
- `NEXT_PUBLIC_WS_URL` (default `ws://localhost:8000`)

If you only tunnel `:3000` but leave those env vars as `localhost`, **phones/remote browsers will break** (they cannot reach your laptop’s localhost for API/WS).

You need either:

1. **Two public hostnames** (recommended for named tunnels): UI + API, or  
2. **One hostname for UI + one for API** via quick tunnels / two processes, then set frontend env to the **public** API/WS URLs and rebuild/restart the frontend.

## Prerequisites

1. Cloudflare account  
2. App already running locally, e.g.:

   ```bash
   docker compose up --build -d
   curl -sf http://localhost:8000/health
   # open http://localhost:3000
   ```

3. Install `cloudflared` ([docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)):

   **Debian/Ubuntu:**

   ```bash
   sudo mkdir -p --mode=0755 /usr/share/keyrings
   curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
   echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
   sudo apt-get update && sudo apt-get install cloudflared
   cloudflared --version
   ```

## Option A — Quick tunnel (fastest)

No domain required. Spawns a random `*.trycloudflare.com` URL.

### A1. Frontend-only smoke test (local API only)

Useful only from the same machine:

```bash
cloudflared tunnel --url http://localhost:3000
```

Copy the `https://….trycloudflare.com` URL from the logs.

Remote visitors will still try `localhost:8000` for API unless you change env (next section).

### A2. Frontend + API both public (recommended quick setup)

Run **two** quick tunnels (two terminals):

```bash
# Terminal 1 — API (HTTP + WebSocket on :8000)
cloudflared tunnel --url http://localhost:8000
# → note https://API_SUBDOMAIN.trycloudflare.com
```

```bash
# Terminal 2 — UI
cloudflared tunnel --url http://localhost:3000
# → note https://UI_SUBDOMAIN.trycloudflare.com
```

Restart the frontend with the **public** API host (WebSocket must use `wss://` on HTTPS pages):

```bash
# If using docker compose frontend:
# set these then rebuild/restart frontend so Next.js bakes/client env picks them up
export NEXT_PUBLIC_API_URL="https://API_SUBDOMAIN.trycloudflare.com"
export NEXT_PUBLIC_WS_URL="wss://API_SUBDOMAIN.trycloudflare.com"
```

Dev compose example (stop stack, then):

```bash
NEXT_PUBLIC_API_URL="https://API_SUBDOMAIN.trycloudflare.com" \
NEXT_PUBLIC_WS_URL="wss://API_SUBDOMAIN.trycloudflare.com" \
docker compose up --build -d
```

Also allow the UI origin on the backend:

```bash
# backend env
P4NT3XIA_CORS_ORIGINS='["https://UI_SUBDOMAIN.trycloudflare.com","http://localhost:3000"]'
```

Then open `https://UI_SUBDOMAIN.trycloudflare.com`.

> Quick tunnel URLs change every run. For a stable hostname, use Option B.

## Option B — Named tunnel (stable hostname)

Requires a domain on Cloudflare ([create local tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-local-tunnel/)).

```bash
cloudflared tunnel login
cloudflared tunnel create p4nt3xia
cloudflared tunnel list   # note UUID
```

Create `~/.cloudflared/config.yml` (paths/UUID from `tunnel create` output):

```yaml
tunnel: <TUNNEL-UUID>
credentials-file: /home/YOU/.cloudflared/<TUNNEL-UUID>.json

ingress:
  # UI
  - hostname: p4nt3xia.example.com
    service: http://localhost:3000
  # API + WebSockets
  - hostname: api.p4nt3xia.example.com
    service: http://localhost:8000
  - service: http_status:404
```

Route DNS:

```bash
cloudflared tunnel route dns p4nt3xia p4nt3xia.example.com
cloudflared tunnel route dns p4nt3xia api.p4nt3xia.example.com
cloudflared tunnel run p4nt3xia
```

Point the frontend at the API hostname:

```bash
NEXT_PUBLIC_API_URL=https://api.p4nt3xia.example.com
NEXT_PUBLIC_WS_URL=wss://api.p4nt3xia.example.com
```

CORS:

```bash
P4NT3XIA_CORS_ORIGINS='["https://p4nt3xia.example.com"]'
```

Optional but strongly recommended: put both hostnames behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) so only your email/IdP can open the app.

## Single-hostname alternative (advanced)

If you put only the frontend on a public host and **proxy `/api` and `/ws` through Next.js rewrites** to the backend, you would need reverse-proxy config in `frontend/next.config` / an edge proxy. This repo’s default wiring uses **separate API URL/WS URL**, so two hostnames (or two quick tunnels) matches the code with minimal changes.

## Auth env (before sharing)

```bash
P4NT3XIA_AUTH_ENABLED=true
P4NT3XIA_JWT_SECRET='use-a-long-random-secret'
P4NT3XIA_BOOTSTRAP_ADMIN_USER=admin
P4NT3XIA_BOOTSTRAP_ADMIN_PASSWORD='long-unique-password'
```

Then sign in at `/login`.

## WebSocket checklist

- Page is `https://` → use `wss://` for `NEXT_PUBLIC_WS_URL` (not `ws://`).
- Tunnel target is still `http://localhost:8000`; `cloudflared` upgrades WSS at the edge.
- Live scan progress uses `/ws/scans/{id}` on the API host.

## Verify

```bash
curl -sf https://api.YOUR_HOST/health
# Browser: open UI URL → Dashboard loads → start a Deep Scan → progress updates live
```

## References

- [Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-local-tunnel/)
- [cloudflared downloads](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
- Quick tunnel: `cloudflared tunnel --url http://localhost:PORT`
