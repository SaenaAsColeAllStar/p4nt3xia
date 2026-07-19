# P4NT3XIA — Agent guide

Personal web pentest platform (Next.js frontend + FastAPI backend). Use this file as the entrypoint for Cursor Cloud Agents and Automations.

## Stack

| Layer | Path | Tech |
|-------|------|------|
| Frontend | `frontend/` | Next.js 14 App Router, Tailwind, TypeScript |
| Backend | `backend/` | FastAPI, SQLAlchemy, SQLite, WebSockets |
| Orchestration | `docker-compose.yml` | Backend `:8000`, frontend `:3000` |
| Spec | `docs/prd/mvp-1.md` | Product requirements / roadmap |

## Modes

- **Deep Scan** (`mode=deep_scan`): non-destructive recon — subfinder, nmap, ffuf, whatweb, nuclei (safe), katana.
- **Attack Mode** (`mode=attack`): authorized exploitation — sqlmap, dalfox, nuclei exploit templates. Always preserve the authorization banner and warning UX.

## Conventions

1. Prefer extending existing tool wrappers (`backend/app/services/deep_scan.py`, `attack.py`) and the shared `ToolRunner` — missing binaries must return `status=skipped`, never crash the orchestrator.
2. Scan progress is broadcast via `ws_manager` to `/ws/scans/{id}`; keep event shape stable (`status`, `progress`, `message`, `finding`, `tool_result`).
3. Findings should include PoC fields (`poc_request`, `poc_response`, `poc_curl`) when the tool provides request/response evidence.
4. Reports: JSON + HTML via `GET /api/scans/{id}/report?format=json|html`. PDF is Phase 3.
5. Do not commit secrets, `.env`, SQLite DB files, `node_modules`, `.venv`, or scan data under `backend/data/`.
6. Only generate or refine attack payloads for authorized testing contexts. Do not add live exploit-against-random-host helpers.

## Local run

```bash
docker compose up --build
# or split:
# backend: cd backend && source .venv/bin/activate && uvicorn app.main:app --reload --port 8000
# frontend: cd frontend && NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

## Roadmap pointer

- Phase 1: Deep Scan MVP — done
- Phase 2: Attack Mode + HTML/JSON reports — current
- Phase 3: hydra, SSRFmap, JWT_Tool, target library polish, PDF, production Docker
