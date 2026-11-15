"""Static attachment inspection. NEVER executes, opens, or extracts attachments.

Only metadata: filename, declared MIME, magic-byte file type, size, SHA-256, and
static risk signals (double extension, MIME/extension mismatch, dangerous type).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from phishlab.parser import Attachment

# Minimal magic-byte signatures (prefix -> label). Signals, not proof.
_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "dos/pe-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip/office-openxml"),
    (b"\xd0\xcf\x11\xe0", "ms-office-legacy"),
    (b"\x1f\x8b", "gzip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF8", "gif"),
    (b"#!", "script-shebang"),
]

# Extensions that can execute code or are commonly abused as lures.
DANGEROUS_EXTENSIONS = {
    "exe",
    "scr",
    "com",
    "pif",
    "bat",
    "cmd",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "hta",
    "ps1",
    "psm1",
    "jar",
    "msi",
    "msp",
    "cpl",
    "lnk",
    "reg",
    "dll",
    "sh",
    "py",
    "apk",
    "iso",
    "img",
    "vhd",
    "ace",
    "cab",
}

# Extension -> expected magic label(s) for mismatch detection.
_EXT_EXPECTED: dict[str, set[str]] = {
    "pdf": {"pdf"},
    "docx": {"zip/office-openxml"},
    "xlsx": {"zip/office-openxml"},
    "pptx": {"zip/office-openxml"},
    "zip": {"zip/office-openxml"},
    "png": {"png"},
    "jpg": {"jpeg"},
    "jpeg": {"jpeg"},
    "gif": {"gif"},
    "doc": {"ms-office-legacy"},
    "xls": {"ms-office-legacy"},
}


@dataclass
class AttachmentReport:
    filename: str | None
    declared_mime: str
    detected_type: str | None
    size: int
    sha256: str
    extensions: list[str]
    flags: list[str] = field(default_factory=list)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect(data: bytes) -> str | None:
    for sig, label in _SIGNATURES:
        if data.startswith(sig):
            return label
    return None


def _extensions(filename: str | None) -> list[str]:
    if not filename:
        return []
    parts = filename.lower().split(".")
    return parts[1:] if len(parts) > 1 else []


def inspect(att: Attachment) -> AttachmentReport:
    exts = _extensions(att.filename)
    detected = _detect(att.payload)
    flags: list[str] = []

    last_ext = exts[-1] if exts else None

    # Double / multiple extension where a non-final ext looks like a doc and final is exec
    if len(exts) >= 2:
        if last_ext in DANGEROUS_EXTENSIONS and exts[-2] in {
            "pdf",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "txt",
            "jpg",
            "png",
            "zip",
            "csv",
        }:
            flags.append(f"double-extension:{exts[-2]}.{last_ext}")

    if last_ext in DANGEROUS_EXTENSIONS:
        flags.append(f"dangerous-extension:{last_ext}")

    if detected in {"dos/pe-executable", "elf-executable", "script-shebang"}:
        flags.append(f"executable-content:{detected}")

    # MIME / magic / extension mismatch
    expected = _EXT_EXPECTED.get(last_ext or "")
    if expected and detected and detected not in expected:
        flags.append(f"ext-magic-mismatch:{last_ext}!={detected}")

    return AttachmentReport(
        filename=att.filename,
        declared_mime=att.content_type,
        detected_type=detected,
        size=att.size,
        sha256=_sha256(att.payload),
        extensions=exts,
        flags=flags,
    )


def inspect_all(attachments: list[Attachment]) -> list[AttachmentReport]:
    return [inspect(a) for a in attachments]
