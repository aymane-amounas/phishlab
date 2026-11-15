# syntax=docker/dockerfile:1

# ---- Stage 1: build the frontend ----
FROM node:20-alpine AS frontend
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: backend runtime ----
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHISHLAB_DB_PATH=/data/phishlab.sqlite3 \
    PHISHLAB_FRONTEND_DIR=/app/frontend_dist

WORKDIR /app
COPY backend/pyproject.toml ./backend/pyproject.toml
COPY backend/phishlab ./backend/phishlab
COPY backend/samples ./backend/samples
RUN pip install --no-cache-dir ./backend

# Built UI from stage 1
COPY --from=frontend /ui/dist ./frontend_dist

# Generate the synthetic corpus and create a non-root user
RUN python backend/samples/generate_corpus.py && \
    useradd -r -u 10001 phishlab && mkdir -p /data && chown -R phishlab:phishlab /data
USER phishlab

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"]

CMD ["uvicorn", "phishlab.main:app", "--host", "0.0.0.0", "--port", "8000"]
