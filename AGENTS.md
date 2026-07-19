# P4NT3XIA

Personal web-based pentest platform. Two services: a FastAPI backend (`backend/`) and a Next.js 14 frontend (`frontend/`). See `README.md` for the product overview, API reference, and standard commands.

## Cursor Cloud specific instructions

### Services and how to run them (local dev, no Docker)

The update script installs backend Python deps into `backend/.venv` and frontend deps into `frontend/node_modules`. Docker is NOT used in the cloud dev setup — run the two services directly.

- Backend (FastAPI, port 8000): from `backend/`, activate the venv then run uvicorn.
  - `source backend/.venv/bin/activate`
  - `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000` (run from inside `backend/`)
  - Health: `http://localhost:8000/health`; API docs: `http://localhost:8000/docs`.
- Frontend (Next.js, port 3000): from `frontend/`, the API/WS URLs must be passed as env vars or it defaults incorrectly.
  - `NEXT_PUBLIC_API_URL=http://localhost:8000 NEXT_PUBLIC_WS_URL=ws://localhost:8000 npm run dev`

The SQLite DB (`backend/data/p4nt3xia.db`) is created automatically on backend startup; no migration step is needed.

### Non-obvious caveats

- The pentest CLI tools (subfinder, nmap, ffuf, whatweb, nuclei, katana) are NOT installed in the cloud dev setup. Deep Scan still runs and completes end-to-end: each missing tool is recorded as an `info` finding with `status: skipped`. This is expected — the scan pipeline, WebSocket progress, DB persistence, and UI all work without the tools. To get real findings, install the tools (see `backend/Dockerfile`) or use `docker compose up --build`.
- `npm run lint` (`next lint`) is NOT configured — there is no committed ESLint config, so the command drops into an interactive setup prompt and cannot run non-interactively. Use `npx tsc --noEmit` from `frontend/` for static type-checking instead.
- Python's `venv` requires the `python3.12-venv` system package (installed via apt during setup); the base image lacks `ensurepip`.
