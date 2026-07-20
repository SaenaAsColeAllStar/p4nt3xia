# P4NT3XIA — Agent guide

Personal web pentest platform (Next.js frontend + FastAPI backend). Use this file as the entrypoint for Cursor Cloud Agents and Automations.

## Stack

| Layer | Path | Tech |
|-------|------|------|
| Frontend | `frontend/` | Next.js 14 App Router, Tailwind, TypeScript |
| Backend | `backend/` | FastAPI, SQLAlchemy, SQLite (optional Postgres), WebSockets, JWT auth |
| Orchestration | `docker-compose.yml` | Backend `:8000`, frontend `:3000`, optional Postgres profile |
| Production | `docker-compose.prod.yml` | Baked images, restart policies |
| Spec | `docs/prd/mvp-1.md` | Product requirements / roadmap |

## Modes

- **Deep Scan** (`mode=deep_scan`): non-destructive recon — subfinder, nmap, ffuf, whatweb, nuclei (safe), katana.
- **Attack Mode** (`mode=attack`): authorized exploitation — sqlmap, dalfox, nuclei exploit, hydra, SSRFmap, JWT_Tool, custom LFI/CMDi/upload/IDOR. Always preserve the authorization banner and warning UX.
- **API Mode**: paste curl / structured HTTP against authorized targets.
- **Templates**: custom payload template builder + runner.
- **Frida**: Android dynamic analysis (skip gracefully if no device / binary).

## Conventions

1. Prefer extending existing tool wrappers (`backend/app/services/deep_scan.py`, `attack.py`, `custom_payloads.py`, `frida_service.py`) and the shared `ToolRunner` — missing binaries must return `status=skipped`, never crash the orchestrator.
2. Scan progress is broadcast via `ws_manager` to `/ws/scans/{id}`; keep event shape stable (`status`, `progress`, `message`, `finding`, `tool_result`).
3. Findings should include PoC fields (`poc_request`, `poc_response`, `poc_curl`) when the tool provides request/response evidence.
4. Reports: JSON + HTML + Markdown + PDF via `GET /api/scans/{id}/report?format=json|html|markdown|pdf`.
5. Do not commit secrets, `.env`, SQLite DB files, `node_modules`, `.venv`, or scan data under `backend/data/`.
6. Only generate or refine attack payloads for authorized testing contexts. Do not add live exploit-against-random-host helpers.
7. Auth is optional (`P4NT3XIA_AUTH_ENABLED`); roles are `admin` / `operator` / `viewer`.

## Local run

```bash
docker compose up --build
# production-style:
# docker compose -f docker-compose.prod.yml up --build -d
# optional Postgres:
# docker compose --profile postgres up --build
# or split:
# backend: cd backend && source .venv/bin/activate && uvicorn app.main:app --reload --port 8000
# frontend: cd frontend && NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

## Roadmap pointer

- Phase 1: Deep Scan MVP — done
- Phase 2: Attack Mode + HTML/JSON reports — done
- Phase 3: hydra, SSRFmap, JWT_Tool, custom payloads, target library, PDF, production Docker — done
- Phase 4: multi-user roles, Frida, API curl mode, custom template builder — current
