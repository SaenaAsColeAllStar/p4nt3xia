# P4NT3XIA

Personal web-based pentest platform. **Phase 4**: multi-user JWT roles, Frida Android analysis, API curl mode, custom payload templates — on top of Deep Scan + Attack Mode, reports, and target library.

## Stack

| Layer | Tech |
|-------|------|
| Frontend | Next.js 14 + Tailwind |
| Backend | FastAPI |
| Database | SQLite (default) / optional Postgres |
| Auth | Optional JWT (`admin` / `operator` / `viewer`) |
| Real-time | WebSocket |
| Deep Scan | Subfinder, Nmap, ffuf, WhatWeb, Nuclei (safe), Katana |
| Attack Mode | sqlmap, Dalfox, Nuclei exploit, hydra, SSRFmap, JWT_Tool, custom LFI/CMDi/upload/IDOR |
| Phase 4 | Frida, API Mode (curl), payload template builder |
| Reports | JSON, HTML, Markdown, PDF (reportlab) |
| Dev | Docker Compose |
| Prod | `docker-compose.prod.yml` |

## Quick start (dev)

```bash
docker compose up --build
```

- Frontend: http://localhost:3000  
- Backend API: http://localhost:8000  
- API docs: http://localhost:8000/docs  
- Health: http://localhost:8000/health  

First backend image build installs scanners and Nuclei templates — expect several minutes.

Optional Postgres:

```bash
P4NT3XIA_DATABASE_URL=postgresql+psycopg2://p4nt3xia:p4nt3xia@postgres:5432/p4nt3xia \
  docker compose --profile postgres up --build
```

## Production Compose

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

Uses `Dockerfile.prod` for both services (no bind-mounts, no `--reload`, restart policies, data volume).

## Auth (optional)

```bash
P4NT3XIA_AUTH_ENABLED=true
P4NT3XIA_JWT_SECRET=long-random-secret
P4NT3XIA_BOOTSTRAP_ADMIN_USER=admin
P4NT3XIA_BOOTSTRAP_ADMIN_PASSWORD=changeme
```

Roles: **viewer** (read), **operator** (run scans / API mode / Frida / templates), **admin** (manage users).

## Local development (without Docker tools)

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Missing binaries are skipped gracefully (`status=skipped` in tool results / findings).

### Frontend

```bash
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000 NEXT_PUBLIC_WS_URL=ws://localhost:8000 npm run dev
```

## Modes

### Deep Scan

1. Subfinder → Nmap → ffuf → WhatWeb → Nuclei (safe) → Katana  
2. Live WebSocket progress  
3. Pick targets from the Target library  

### Attack Mode

1. Confirm authorization checkbox (API rejects without `options.authorized=true`)  
2. Optional auth header (required for JWT_Tool)  
3. Vectors: sqlmap / Dalfox / Nuclei / hydra / SSRFmap / JWT_Tool / LFI / CMDi / upload / IDOR  
4. Findings with PoC curl, CVSS, detail page  
5. Reports: JSON + HTML + Markdown + PDF  

### API Mode / Templates / Frida

- `/api-mode` — paste curl, parse + execute  
- `/templates` — build and run custom payload templates  
- `/frida` — Android dynamic instrumentation (USB/emulator)  

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard` | Stats + recent scans |
| GET/POST/PATCH/DELETE | `/api/targets` | Target library |
| GET | `/api/targets/{id}/scans` | Scans for a target |
| POST | `/api/scans/deep` | Start Deep Scan |
| POST | `/api/scans/attack` | Start Attack Mode (`options.authorized` required) |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/{id}` | Scan + findings + tool results |
| GET | `/api/scans/{id}/findings/{fid}` | Finding detail |
| POST | `/api/scans/{id}/cancel` | Cancel running scan |
| GET | `/api/scans/{id}/report?format=json\|html\|pdf\|markdown` | Report export |
| POST | `/api/auth/login` | JWT login |
| GET | `/api/auth/status` | Auth enabled + current user |
| GET/POST | `/api/templates` | Payload templates |
| POST | `/api/templates/{id}/run` | Run template (`authorized=true`) |
| POST | `/api/api-mode/parse` | Parse curl |
| POST | `/api/api-mode/request` | Execute HTTP request |
| GET/POST | `/api/frida/*` | Devices, samples, run script |
| WS | `/ws/scans/{id}` | Live progress |

## Cloudflare Tunnel

See `docs/cloudflare-tunnel.md` to expose a running stack via cloudflared.

## Agent / Cloud setup

See `AGENTS.md` and `docs/cloud-agent-setup.md` for Cursor Cloud Agents and Automations.

## Warning

Only scan systems you are authorized to test. Attack Mode, API Mode (non-GET), template runs, and Frida require explicit authorization confirmation.
