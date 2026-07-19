# P4NT3XIA

Personal web-based pentest platform. **Phase 2**: Deep Scan + Attack Mode with JSON/HTML reports.

## Stack

| Layer | Tech |
|-------|------|
| Frontend | Next.js 14 + Tailwind |
| Backend | FastAPI |
| Database | SQLite + SQLAlchemy |
| Real-time | WebSocket |
| Deep Scan | Subfinder, Nmap, ffuf, WhatWeb, Nuclei (safe), Katana |
| Attack Mode | sqlmap, Dalfox, Nuclei (high/critical / exploit tags) |
| Dev | Docker Compose |

## Quick start

```bash
docker compose up --build
```

- Frontend: http://localhost:3000  
- Backend API: http://localhost:8000  
- API docs: http://localhost:8000/docs  
- Health: http://localhost:8000/health  

First backend image build installs scanners and Nuclei templates — expect several minutes.

## Local development (without Docker tools)

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# optional attack tools: pip install sqlmap; go install github.com/hahwul/dalfox/v2@latest
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

### Attack Mode

1. Confirm authorization checkbox  
2. Optional auth header  
3. Vectors: sqlmap / Dalfox / Nuclei exploit  
4. Findings with PoC curl, CVSS, detail page  
5. Reports: JSON + interactive HTML  

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard` | Stats + recent scans |
| GET/POST | `/api/targets` | Target library |
| POST | `/api/scans/deep` | Start Deep Scan |
| POST | `/api/scans/attack` | Start Attack Mode (`options.authorized` required) |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/{id}` | Scan + findings + tool results |
| GET | `/api/scans/{id}/findings/{fid}` | Finding detail |
| POST | `/api/scans/{id}/cancel` | Cancel running scan |
| GET | `/api/scans/{id}/report?format=json\|html` | Report export |
| WS | `/ws/scans/{id}` | Live progress |

## Agent / Cloud setup

See `AGENTS.md` and `docs/cloud-agent-setup.md` for Cursor Cloud Agents and Automations.

## Warning

Only scan systems you are authorized to test. Attack Mode requires an explicit authorization confirmation and shows a persistent warning banner.
