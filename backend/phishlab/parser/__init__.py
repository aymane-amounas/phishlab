"""Email + MIME parser built on the Python stdlib `email` package (lax policy).

Design goals:
- Never raise on malformed input; capture problems as warnings/findings instead.
- Preserve the ORIGINAL header representation alongside decoded values.
- Bound MIME depth and part count (DoS defense).
- Treat authentication results as SENDER-REPORTED, never as verified.
"""

from __future__ import annotations

import email
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import Message

from phishlab.config import settings


@dataclass
class Header:
    name: str
    raw: str  # original representation (best effort)
    decoded: str  # decoded/unfolded value for display


@dataclass
class MimePart:
    content_type: str
    content_transfer_encoding: str | None
    filename: str | None
    is_attachment: bool
    size: int
    charset: str | None
    depth: int
    # text content for text/* parts only; HTML kept as SOURCE (never rendered)
    text: str | None = None


@dataclass
class AuthResults:
    raw: str | None = None  # original Authentication-Results header(s)
    spf: str | None = None  # pass/fail/softfail/neutral/none (sender-reported)
    dkim: str | None = None
    dmarc: str | None = None
    verified: bool = False  # ALWAYS False in v1 — we do not independently verify


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size: int
    payload: bytes  # for static hashing / magic-byte inspection only


@dataclass
class ParsedEmail:
    headers: list[Header] = field(default_factory=list)
    from_: str | None = None
    to: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None
    received: list[str] = field(default_factory=list)
    auth: AuthResults = field(default_factory=AuthResults)
    parts: list[MimePart] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    body_text: str | None = None
    body_html: str | None = None  # source only
    warnings: list[str] = field(default_factory=list)

    def header_values(self, name: str) -> list[str]:
        name = name.lower()
        return [h.decoded for h in self.headers if h.name.lower() == name]


def _decode(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def parse(raw: bytes) -> ParsedEmail:
    """Parse raw bytes into a ParsedEmail. Never raises on content problems."""
    out = ParsedEmail()
    try:
        msg: Message = email.message_from_bytes(raw, policy=policy.compat32)
    except Exception as exc:  # pragma: no cover - stdlib is very tolerant
        out.warnings.append(f"Top-level parse error: {exc!r}")
        return out

    # Headers: preserve order + duplicates, keep raw and decoded.
    try:
        for name, value in msg.items():
            out.headers.append(Header(name=name, raw=str(value), decoded=_decode(str(value))))
    except Exception as exc:
        out.warnings.append(f"Header enumeration error: {exc!r}")

    def first(name: str) -> str | None:
        vals = out.header_values(name)
        return vals[0] if vals else None

    out.from_ = first("from")
    out.to = first("to")
    out.reply_to = first("reply-to")
    out.return_path = first("return-path")
    out.subject = first("subject")
    out.date = first("date")
    out.message_id = first("message-id")
    out.received = out.header_values("received")

    _parse_auth(out)
    _walk(msg, out, depth=0)

    if not out.headers:
        out.warnings.append("No headers found; artifact may be empty or malformed.")
    return out


def _parse_auth(out: ParsedEmail) -> None:
    ar = out.header_values("authentication-results")
    out.auth.raw = "\n".join(ar) if ar else None
    blob = " ".join(ar).lower()
    # Also consider dedicated Received-SPF.
    rspf = " ".join(out.header_values("received-spf")).lower()

    def grab(mech: str, text: str) -> str | None:
        # find "mech=result" tokens (sender-reported)
        marker = mech + "="
        idx = text.find(marker)
        if idx == -1:
            return None
        rest = text[idx + len(marker) :].lstrip()
        token = ""
        for ch in rest:
            if ch.isalpha():
                token += ch
            else:
                break
        return token or None

    out.auth.spf = grab("spf", blob) or (rspf.split()[0] if rspf else None)
    out.auth.dkim = grab("dkim", blob)
    out.auth.dmarc = grab("dmarc", blob)
    out.auth.verified = False  # never claim verification in v1


def _walk(msg: Message, out: ParsedEmail, depth: int) -> None:
    if depth > settings.max_mime_depth:
        out.warnings.append(f"MIME nesting exceeded cap ({settings.max_mime_depth}); truncated.")
        return
    if len(out.parts) >= settings.max_mime_parts:
        out.warnings.append(f"MIME part count exceeded cap ({settings.max_mime_parts}); truncated.")
        return

    ctype = (msg.get_content_type() or "application/octet-stream").lower()
    cte = msg.get("Content-Transfer-Encoding")
    charset = msg.get_content_charset()
    disp = (msg.get_content_disposition() or "").lower()
    filename = msg.get_filename()
    if filename:
        filename = _decode(filename)

    if msg.is_multipart():
        out.parts.append(
            MimePart(
                content_type=ctype,
                content_transfer_encoding=str(cte) if cte else None,
                filename=None,
                is_attachment=False,
                size=0,
                charset=charset,
                depth=depth,
            )
        )
        for sub in msg.get_payload():
            if isinstance(sub, Message):
                _walk(sub, out, depth + 1)
        return

    # Leaf part
    try:
        payload = msg.get_payload(decode=True)
    except Exception as exc:
        payload = None
        out.warnings.append(f"Payload decode error in {ctype}: {exc!r}")
    size = len(payload) if payload else 0
    is_attachment = disp == "attachment" or bool(filename)

    part = MimePart(
        content_type=ctype,
        content_transfer_encoding=str(cte) if cte else None,
        filename=filename,
        is_attachment=is_attachment,
        size=size,
        charset=charset,
        depth=depth,
    )

    if ctype.startswith("text/") and payload is not None and not is_attachment:
        text = _safe_text(payload, charset)
        if ctype == "text/html":
            out.body_html = out.body_html or text  # SOURCE only, never rendered
        else:
            out.body_text = out.body_text or text
        part.text = text

    if is_attachment:
        out.attachments.append(
            Attachment(
                filename=filename,
                content_type=ctype,
                size=size,
                payload=payload or b"",
            )
        )
    out.parts.append(part)


def _safe_text(payload: bytes, charset: str | None) -> str:
    for enc in (charset, "utf-8", "latin-1"):
        if not enc:
            continue
        try:
            return payload.decode(enc, errors="replace")
        except (LookupError, ValueError):
            continue
    return payload.decode("utf-8", errors="replace")
