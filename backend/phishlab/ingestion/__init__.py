"""Artifact ingestion: validate, size-limit, hash. Treats input as hostile."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from phishlab.config import settings


class IngestionError(ValueError):
    """Raised when an artifact is rejected before parsing."""


@dataclass(frozen=True)
class Artifact:
    raw: bytes
    sha256: str
    size: int
    source_kind: str  # "eml" | "headers" | "text"
    declared_filename: str | None = None


def _sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def ingest_bytes(
    data: bytes, source_kind: str = "eml", declared_filename: str | None = None
) -> Artifact:
    """Validate size, compute hash, wrap raw bytes. No parsing here."""
    if not data:
        raise IngestionError("Empty artifact.")
    size = len(data)
    if size > settings.max_upload_bytes:
        raise IngestionError(
            f"Artifact too large: {size} bytes > limit {settings.max_upload_bytes}."
        )
    if source_kind not in {"eml", "headers", "text"}:
        raise IngestionError(f"Unsupported source kind: {source_kind!r}")
    return Artifact(
        raw=data,
        sha256=_sha256(data),
        size=size,
        source_kind=source_kind,
        declared_filename=_safe_name(declared_filename),
    )


def ingest_text(text: str, source_kind: str = "headers") -> Artifact:
    return ingest_bytes(text.encode("utf-8", "surrogateescape"), source_kind=source_kind)


def _safe_name(name: str | None) -> str | None:
    """Strip any path components from a declared filename. Never trust it."""
    if not name:
        return None
    # Defeat path traversal: keep the basename only, drop separators.
    base = name.replace("\\", "/").split("/")[-1]
    base = base.strip().replace("\x00", "")
    return base[:255] or None
