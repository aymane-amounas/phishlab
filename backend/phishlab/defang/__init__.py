"""Safe URL/indicator defanging and component breakdown.

Defanging makes an indicator non-clickable and non-resolvable in copy/paste contexts:
    https://evil.example.com/login  ->  hxxps://evil[.]example[.]com/login
Refanging is the inverse, used ONLY for controlled internal processing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_SCHEME_RE = re.compile(r"^(https?)://", re.IGNORECASE)


def defang_url(url: str) -> str:
    s = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
    s = re.sub(r"^http://", "hxxp://", s, flags=re.IGNORECASE)
    return s.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_email(addr: str) -> str:
    return addr.replace("@", "[@]").replace(".", "[.]")


def refang(value: str) -> str:
    """Reverse common defang patterns. For internal controlled use only."""
    s = value
    s = s.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace(" dot ", ".")
    s = s.replace("[@]", "@").replace("(@)", "@").replace("[at]", "@")
    s = re.sub(r"^hxxps://", "https://", s, flags=re.IGNORECASE)
    s = re.sub(r"^hxxp://", "http://", s, flags=re.IGNORECASE)
    s = re.sub(r"^hxxps?\[:\]//", "https://", s, flags=re.IGNORECASE)
    return s


@dataclass
class UrlBreakdown:
    original: str
    scheme: str
    userinfo: str | None
    host: str | None
    port: int | None
    path: str
    query: str
    fragment: str
    is_ip_literal: bool
    defanged: str


def _is_ip_literal(host: str) -> bool:
    if not host:
        return False
    if host.startswith("[") and host.endswith("]"):  # IPv6 literal
        return True
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def breakdown(url: str) -> UrlBreakdown:
    parts = urlsplit(url if _SCHEME_RE.match(url) else "http://" + url)
    host = parts.hostname
    # parts.port raises ValueError on an out-of-range port (e.g. a crafted :999999 in a
    # hostile email). Input must never crash analysis, so treat a bad port as absent.
    try:
        port = parts.port
    except ValueError:
        port = None
    return UrlBreakdown(
        original=url,
        scheme=parts.scheme,
        userinfo=parts.username if parts.username else None,
        host=host,
        port=port,
        path=parts.path or "",
        query=parts.query or "",
        fragment=parts.fragment or "",
        is_ip_literal=_is_ip_literal(host or ""),
        defanged=defang_url(url),
    )
