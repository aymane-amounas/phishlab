# Deployment

PhishLab is designed to run **local-only**. Do not expose it to untrusted networks.

## Docker (recommended)

```bash
docker compose up --build
# UI + API at http://127.0.0.1:8000
```

- The container binds to `127.0.0.1:8000` on the host (see `docker-compose.yml`).
- A single image builds the frontend (Node stage) and serves it from the API (Python
  stage).
- Runs as a non-root user, read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`.
- Case data persists in the named volume `phishlab_data` (mounted at `/data`).

### Persistence check

```bash
docker compose up --build -d
# create a case via the UI, then:
docker compose restart
# the case is still listed -> persistence verified
```

### Health

`GET /api/health` returns `{"status":"ok","network_lookups_enabled":false}`. The image
has a `HEALTHCHECK` that polls it.

## Local (no Docker)

See [development.md](development.md). Run uvicorn bound to `127.0.0.1` and either run the
Vite dev server or serve the built `frontend/dist` via `PHISHLAB_FRONTEND_DIR`.

## Backup & recovery

- **Backup**: copy the SQLite file (volume `phishlab_data` -> `/data/phishlab.sqlite3`).
  ```bash
  docker run --rm -v phishlab_data:/data -v "$PWD":/backup alpine \
    cp /data/phishlab.sqlite3 /backup/phishlab-backup.sqlite3
  ```
- **Recovery**: stop the service, restore the file into the volume, start again.

## Upgrade

```bash
git pull
docker compose build --no-cache
docker compose up -d
```

The SQLite schema is created idempotently (`CREATE TABLE IF NOT EXISTS` + indexes).
Backup the database before upgrading.

## Offline operation

Static analysis requires no internet. The image bundles everything; after build, pull
the host off the network and analysis still works. Network lookups remain disabled.

## CI activation note

CI workflows are staged in `.github-pending/workflows/` because the active GitHub token
lacks the `workflow` scope. To activate: move the directory to `.github/workflows/` and
push with a token that has `workflow` scope (or commit it via the GitHub web UI).
