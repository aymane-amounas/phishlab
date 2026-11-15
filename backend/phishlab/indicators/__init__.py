"""Indicator extraction + normalization. Static only - never resolves or fetches.

Extracts URLs, domains, IPv4/IPv6 addresses, and email addresses from an email, keeping
each indicator tied to WHERE it was found (source location) for evidence. Flags
punycode/IDN, suspicious Unicode, IP-literal hosts, unusual ports, and URL userinfo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from phishlab.config import settings
from phishlab.defang import breakdown, defang_domain, defang_email, defang_url
from phishlab.parser import ParsedEmail

# Bounded regexes (no catastrophic backtracking; inputs are length-capped before scan).
URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\)\]\}]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
ZERO_WIDTH = {"​", "‌", "‍", "﻿", "⁠"}


@dataclass
class Indicator:
    type: str  # url | domain | ipv4 | ipv6 | email
    value: str
    normalized: str
    defanged: str
    source: str  # where found, e.g. "header:reply-to", "body:text"
    flags: list[str] = field(default_factory=list)


@dataclass
class IndicatorSet:
    urls: list[Indicator] = field(default_factory=list)
    domains: list[Indicator] = field(default_factory=list)
    ipv4: list[Indicator] = field(default_factory=list)
    ipv6: list[Indicator] = field(default_factory=list)
    emails: list[Indicator] = field(default_factory=list)

    def all(self) -> list[Indicator]:
        return [*self.urls, *self.domains, *self.ipv4, *self.ipv6, *self.emails]


def _cap(text: str | None) -> str:
    if not text:
        return ""
    return text[: settings.max_field_scan_bytes]


def extract(parsed: ParsedEmail) -> IndicatorSet:
    sources: list[tuple[str, str]] = []
    for h in parsed.headers:
        sources.append((f"header:{h.name.lower()}", h.decoded))
    if parsed.subject:
        sources.append(("header:subject", parsed.subject))
    if parsed.body_text:
        sources.append(("body:text", parsed.body_text))
    if parsed.body_html:
        sources.append(("body:html", parsed.body_html))

    iset = IndicatorSet()
    seen_domains: set[str] = set()

    for source, raw in sources:
        text = _cap(raw)

        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(".,);]")
            ind = _url_indicator(url, source)
            iset.urls.append(ind)
            d = _domain_of_url(url)
            if d and d.lower() not in seen_domains:
                seen_domains.add(d.lower())
                iset.domains.append(_domain_indicator(d, f"{source} (url)"))

        for m in EMAIL_RE.finditer(text):
            addr = m.group(0)
            iset.emails.append(
                Indicator(
                    type="email",
                    value=addr,
                    normalized=addr.lower(),
                    defanged=defang_email(addr),
                    source=source,
                    flags=_domain_flags(addr.split("@")[-1]),
                )
            )
            dom = addr.split("@")[-1]
            if dom.lower() not in seen_domains:
                seen_domains.add(dom.lower())
                iset.domains.append(_domain_indicator(dom, f"{source} (email)"))

        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            if _valid_ipv4(ip):
                iset.ipv4.append(Indicator("ipv4", ip, ip, ip.replace(".", "[.]"), source))

        for m in IPV6_RE.finditer(text):
            ip = m.group(0)
            if ip.count(":") >= 2:
                iset.ipv6.append(Indicator("ipv6", ip, ip.lower(), ip, source))

    return iset


def _url_indicator(url: str, source: str) -> Indicator:
    bd = breakdown(url)
    flags: list[str] = []
    if bd.is_ip_literal:
        flags.append("ip-based-url")
    if bd.userinfo:
        flags.append("url-userinfo")
    if bd.port and bd.port not in (80, 443):
        flags.append(f"unusual-port:{bd.port}")
    if bd.host:
        flags.extend(_domain_flags(bd.host))
    return Indicator(
        type="url",
        value=url,
        normalized=url,
        defanged=defang_url(url),
        source=source,
        flags=flags,
    )


def _domain_indicator(domain: str, source: str) -> Indicator:
    return Indicator(
        type="domain",
        value=domain,
        normalized=domain.lower().rstrip("."),
        defanged=defang_domain(domain),
        source=source,
        flags=_domain_flags(domain),
    )


def _domain_of_url(url: str) -> str | None:
    bd = breakdown(url)
    if bd.host and not bd.is_ip_literal:
        return bd.host
    return None


def _domain_flags(domain: str) -> list[str]:
    flags: list[str] = []
    labels = domain.split(".")
    if any(lbl.lower().startswith("xn--") for lbl in labels):
        flags.append("punycode-idn")
        decoded = _decode_punycode(domain)
        if decoded and decoded != domain:
            flags.append(f"idn-decoded:{decoded}")
    if any(ord(ch) > 127 for ch in domain):
        flags.append("non-ascii-domain")
    if any(ch in ZERO_WIDTH for ch in domain):
        flags.append("zero-width-char")
    return flags


def _decode_punycode(domain: str) -> str | None:
    try:
        return domain.encode("ascii").decode("idna")
    except Exception:
        return None


def _valid_ipv4(ip: str) -> bool:
    try:
        return all(0 <= int(o) <= 255 for o in ip.split("."))
    except ValueError:
        return False
