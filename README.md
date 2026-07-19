# P4NT3XIA

Personal web-based pentest platform. Phase 1 MVP: **Deep Scan** with live WebSocket progress.

## Stack

| Layer | Tech |
|-------|------|
| Frontend | Next.js 14 + Tailwind |
| Backend | FastAPI |
| Database | SQLite + SQLAlchemy |
| Real-time | WebSocket |
| Tools | Subfinder, Nmap, ffuf, WhatWeb, Nuclei (safe), Katana |
| Dev | Docker Compose |

## Quick start

```bash
docker compose up --build
```

- Frontend: http://localhost:3000  
- Backend API: http://localhost:8000  
- API docs: http://localhost:8000/docs  
- Health: http://localhost:8000/health  

First backend image build installs Go-based scanners and Nuclei templates — expect several minutes.

## Local development (without Docker tools)

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Missing binaries are skipped gracefully (status `skipped` in tool results / findings).

### Frontend

```bash
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000 NEXT_PUBLIC_WS_URL=ws://localhost:8000 npm run dev
```

## Deep Scan pipeline

1. **Subfinder** — subdomain enum  
2. **Nmap** — top 100 ports (`-sT -sV -T3`)  
3. **ffuf** — directory fuzz (small wordlist, safe status codes)  
4. **WhatWeb** — technology detection  
5. **Nuclei** — `-severity info,low,medium -etags exploit,intrusive,dos`  
6. **Katana** — crawl (no form submission)

## API (Phase 1)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard` | Stats + recent scans |
| GET/POST | `/api/targets` | Target library |
| POST | `/api/scans/deep` | Start Deep Scan |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/{id}` | Scan + findings + tool results |
| POST | `/api/scans/{id}/cancel` | Cancel running scan |
| GET | `/api/scans/{id}/report` | JSON report export |
| WS | `/ws/scans/{id}` | Live progress |

## Project layout

Matches `docs/prd/mvp-1.md` §13:

```
frontend/     # Next.js (dashboard, deep-scan, attack-mode stub, history)
backend/      # FastAPI + tool wrappers + wordlist
docker-compose.yml
docs/prd/
```

## Phase 1 scope vs later

| In MVP | Deferred |
|--------|----------|
| Dashboard, Deep Scan, WebSocket, results tables | Attack Mode tools |
| SQLite persistence | Postgres, Celery/Redis |
| JSON report endpoint | PDF / HTML reports |
| Docker Compose for dev | Production hardening |

## Warning

Only scan systems you are authorized to test. Deep Scan is designed to be non-destructive; Attack Mode (Phase 2) will require an explicit authorization banner.
