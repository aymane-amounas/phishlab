# Development

## Prerequisites

- Python 3.11+ (tested on 3.14)
- Node 18+ for the frontend

## Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Generate the synthetic sample corpus (idempotent)
python samples/generate_corpus.py

# Run tests, lint, format-check
pytest
ruff check .
ruff format --check .

# Run the API (localhost only)
uvicorn phishlab.main:app --host 127.0.0.1 --port 8000
```

## Frontend

```bash
cd frontend
npm install
npm run dev        # http://127.0.0.1:5173 (proxies /api to :8000)
npm run build      # outputs frontend/dist
```

To serve the built UI from the backend as a single process, point
`PHISHLAB_FRONTEND_DIR` at the build:

```bash
PHISHLAB_FRONTEND_DIR=../frontend/dist uvicorn phishlab.main:app --host 127.0.0.1 --port 8000
```

## Module layout

See [architecture.md](architecture.md). The modules are import-isolated and the data runs
through them in order:
`ingestion -> parser -> indicators/attachments -> detection -> cases -> reporting`, with
`network` kept out of the default path.

## Configuration

Everything is set through environment variables:

| Var | Default | Meaning |
|---|---|---|
| `PHISHLAB_MAX_UPLOAD_BYTES` | 26214400 | Max artifact size (25 MB) |
| `PHISHLAB_MAX_MIME_DEPTH` | 20 | MIME nesting cap |
| `PHISHLAB_MAX_MIME_PARTS` | 200 | MIME part cap |
| `PHISHLAB_MAX_FIELD_SCAN_BYTES` | 1000000 | Per-field indicator scan cap |
| `PHISHLAB_DB_PATH` | ./data/phishlab.sqlite3 | SQLite path |
| `PHISHLAB_RETENTION_DAYS` | 0 | 0 = keep until deleted |
| `PHISHLAB_ENABLE_NETWORK_LOOKUPS` | false | Opt-in SSRF-sensitive module |
| `PHISHLAB_FRONTEND_DIR` | (unset) | Serve a built frontend from the API |

## Adding a detection rule

1. Add a `_r_*` function in `phishlab/detection/__init__.py` that returns `list[Finding]`.
2. Register it in `RULES`.
3. Add a test in `tests/test_attachments_detection.py`. A rule is not done without one.
4. Document it in [detection-rules.md](detection-rules.md).
