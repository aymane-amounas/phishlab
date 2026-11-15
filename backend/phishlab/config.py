"""Runtime configuration. All defaults are safe and offline."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int(env: str, default: int) -> int:
    try:
        return int(os.environ[env])
    except (KeyError, ValueError):
        return default


def _bool(env: str, default: bool) -> bool:
    val = os.environ.get(env)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Ingestion
    max_upload_bytes: int = _int("PHISHLAB_MAX_UPLOAD_BYTES", 25 * 1024 * 1024)  # 25 MB
    # Parser limits (DoS defense)
    max_mime_depth: int = _int("PHISHLAB_MAX_MIME_DEPTH", 20)
    max_mime_parts: int = _int("PHISHLAB_MAX_MIME_PARTS", 200)
    # Indicator extraction caps
    max_field_scan_bytes: int = _int("PHISHLAB_MAX_FIELD_SCAN_BYTES", 1_000_000)
    # Storage
    db_path: str = os.environ.get("PHISHLAB_DB_PATH", "./data/phishlab.sqlite3")
    retention_days: int = _int("PHISHLAB_RETENTION_DAYS", 0)  # 0 = keep until deleted
    # Network module - OFF by default. SSRF-sensitive.
    network_lookups_enabled: bool = _bool("PHISHLAB_ENABLE_NETWORK_LOOKUPS", False)
    # CORS / binding is handled at the server/deployment layer (localhost by default)


settings = Settings()
