"""Opt-in, SSRF-hardened redirect inspection. DISABLED by default.

This module is the highest-risk surface in PhishLab. It ships disabled
(PHISHLAB_ENABLE_NETWORK_LOOKUPS=false). Even when enabled, every destination — the
initial host AND every redirect hop, by resolved IP — is validated against blocked
ranges before any connection. The guard functions are unit-tested regardless of whether
the feature is enabled.

v1 intentionally does NOT perform live fetches; `inspect_redirects` refuses unless
explicitly enabled, and the safe-destination guard is the reusable, tested core.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from phishlab.config import settings

ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 256 * 1024
CONNECT_TIMEOUT = 5.0
TOTAL_TIMEOUT = 15.0


class NetworkDisabled(RuntimeError):
    pass


class UnsafeDestination(ValueError):
    pass


@dataclass
class DestinationCheck:
    host: str
    resolved_ips: list[str]
    safe: bool
    reason: str | None = None


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (ip.version == 6 and ip.ipv4_mapped is not None and _is_blocked_ip(ip.ipv4_mapped))
    )


def check_scheme(scheme: str) -> None:
    if scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeDestination(f"Scheme not allowed: {scheme!r} (only http/https).")


def check_destination(host: str, *, resolver=socket.getaddrinfo) -> DestinationCheck:
    """Resolve host and verify EVERY resolved IP is public. Defends against DNS rebinding
    by requiring the caller to re-check the actual connected IP (see connect flow)."""
    if not host:
        raise UnsafeDestination("Empty host.")
    # IP literal?
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        safe = not _is_blocked_ip(ip)
        return DestinationCheck(host, [str(ip)], safe, None if safe else "blocked IP range")
    except ValueError:
        pass

    try:
        infos = resolver(host, None)
    except OSError as exc:
        raise UnsafeDestination(f"DNS resolution failed for {host!r}: {exc}") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise UnsafeDestination(f"No DNS records for {host!r}.")
    for ip_str in ips:
        if _is_blocked_ip(ipaddress.ip_address(ip_str)):
            return DestinationCheck(host, ips, False, f"resolves to blocked IP {ip_str}")
    return DestinationCheck(host, ips, True)


def inspect_redirects(url: str) -> dict:
    """Would follow redirects under strict SSRF controls. Refuses unless explicitly
    enabled. Not performed in v1."""
    if not settings.network_lookups_enabled:
        raise NetworkDisabled(
            "Network lookups are disabled. Enable PHISHLAB_ENABLE_NETWORK_LOOKUPS only "
            "after reviewing docs/network-safety.md."
        )
    # When implemented: resolve+check_destination at each hop, no cookies/creds, size/time
    # caps, re-validate the connected socket's peer IP (DNS-rebinding defense).
    raise NotImplementedError("Live redirect inspection is deferred to M10.")
