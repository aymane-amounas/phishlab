# Deployment

PhishLab is meant to run local-only. Do not expose it to untrusted networks.

## Docker (recommended)

```bash
docker compose up --build
# UI + API at http://127.0.0.1:8000
```

The container binds to `127.0.0.1:8000` on the host (see `docker-compose.yml`). A single
image builds the frontend in a Node stage and serves it from the API in the Python stage.
It runs as a non-root user with a read-only root filesystem, `cap_drop: ALL`, and
`no-new-privileges`. Case data persists in the named volume `phishlab_data`, mounted at
`/data`.

### Persistence check

```bash
docker compose up --build -d
# create a case via the UI, then:
docker compose restart
# the case is still listed -> persistence verified
```

### Health

`GET /api/health` returns `{"status":"ok","network_lookups_enabled":false}`. The image has
a `HEALTHCHECK` that polls it.

## Local (no Docker)

See [development.md](development.md). Run uvicorn bound to `127.0.0.1` and either run the
Vite dev server or serve the built `frontend/dist` through `PHISHLAB_FRONTEND_DIR`.

## Backup and recovery

To back up, copy the SQLite file out of the `phishlab_data` volume
(`/data/phishlab.sqlite3`):

```bash
docker run --rm -v phishlab_data:/data -v "$PWD":/backup alpine \
  cp /data/phishlab.sqlite3 /backup/phishlab-backup.sqlite3
```

To recover, stop the service, restore the file into the volume, and start it again.

## Upgrade

```bash
git pull
docker compose build --no-cache
docker compose up -d
```

The SQLite schema is created idempotently (`CREATE TABLE IF NOT EXISTS` plus indexes).
Back up the database before upgrading anyway.

## Offline operation

Static analysis needs no internet. The image bundles everything, so after a build you can
pull the host off the network and analysis still works. Network lookups stay disabled.

## CI

Tests, ruff, and a secret scan run on GitHub Actions via `.github/workflows/ci.yml`. If
you fork the repo, pushing that workflow needs a token with `workflow` scope.
