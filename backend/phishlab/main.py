"""FastAPI application entrypoint. Local-only by default; security headers on all responses."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from phishlab import __version__
from phishlab.api import router
from phishlab.banner import print_banner
from phishlab.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    print_banner()
    yield


app = FastAPI(
    title="PhishLab",
    version=__version__,
    description="Safe, offline-first phishing investigation workbench.",
    lifespan=lifespan,
)

# CORS: only the local dev frontend by default.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Reject oversized bodies before they are buffered. Content-Length is advisory (absent on
# chunked uploads), so the per-field size checks in ingestion remain the hard limit.
_MAX_BODY_BYTES = settings.max_upload_bytes + 1 * 1024 * 1024  # upload cap + multipart overhead


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > _MAX_BODY_BYTES:
                return JSONResponse({"detail": "Request body too large."}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    # API responses: lock everything down (no scripts, no remote resources).
    # UI shell/assets: allow same-origin scripts/styles only (still no remote content).
    if request.url.path.startswith("/api"):
        csp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    else:
        csp = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
    resp.headers.setdefault("Content-Security-Policy", csp)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


app.include_router(router)

# Optionally serve a built frontend (single-container deployment).
# Mounted last so /api/* routes always take precedence. html=True serves index.html at
# "/" and exposes static files like /logo.png and /assets/*.
_FRONTEND_DIR = os.environ.get("PHISHLAB_FRONTEND_DIR", "")
if _FRONTEND_DIR and os.path.isdir(_FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")
