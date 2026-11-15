"""FastAPI application entrypoint. Local-only by default; security headers on all responses."""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from phishlab import __version__
from phishlab.api import router

app = FastAPI(
    title="PhishLab",
    version=__version__,
    description="Safe, offline-first phishing investigation workbench.",
)

# CORS: only the local dev frontend by default.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    # Strict CSP: no remote resources, no inline scripts for API responses.
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    )
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


app.include_router(router)

# Optionally serve a built frontend (single-container deployment).
_FRONTEND_DIR = os.environ.get("PHISHLAB_FRONTEND_DIR", "")
if _FRONTEND_DIR and os.path.isdir(_FRONTEND_DIR):
    app.mount(
        "/assets", StaticFiles(directory=os.path.join(_FRONTEND_DIR, "assets")), name="assets"
    )

    @app.get("/")
    def index():
        return FileResponse(os.path.join(_FRONTEND_DIR, "index.html"))
