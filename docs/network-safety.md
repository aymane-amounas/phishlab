# Network Safety (SSRF model)

The optional redirect-inspection module is the highest-risk surface in PhishLab. It is
**disabled by default** (`PHISHLAB_ENABLE_NETWORK_LOOKUPS=false`) and v1 does **not**
perform live fetches. The reusable, tested core is the safe-destination guard.

## Why this is dangerous

A defensive tool that follows attacker-supplied URLs can be turned into a Server-Side
Request Forgery (SSRF) primitive: the attacker makes *your* server request internal
services (cloud metadata at `169.254.169.254`, internal admin panels, `localhost`).

## Controls (enforced in `phishlab/network`)

- **Scheme allowlist**: only `http`/`https` (`check_scheme`). `file`, `gopher`, `data`,
  etc. are rejected.
- **Destination validation** (`check_destination`): the host is resolved and **every
  resolved IP** is checked. Blocked ranges: private, loopback, link-local
  (incl. `169.254.0.0/16`), multicast, reserved, unspecified, and IPv4-mapped IPv6 of
  any of these.
- **DNS-rebinding defense**: validation happens on the resolved IPs, and a real
  implementation must re-validate the *actually connected* peer IP before sending the
  request (documented in code).
- **Redirect cap** (`MAX_REDIRECTS=5`), each hop re-validated from scratch.
- **Response caps**: `MAX_RESPONSE_BYTES=256 KB`, `CONNECT_TIMEOUT=5s`,
  `TOTAL_TIMEOUT=15s`.
- **No credentials**: cookies/authorization are never forwarded; bodies are never
  executed; no arbitrary proxy from untrusted input.

## Current behaviour

`inspect_redirects()` raises `NetworkDisabled` unless explicitly enabled, and
`NotImplementedError` (deferred to M10) even when enabled. The guard functions
(`check_scheme`, `check_destination`) are fully implemented and unit-tested regardless.

## Tests

`tests/test_cases_network.py` verifies the scheme allowlist, blocking of
private/loopback/link-local/`169.254.169.254`/`::1`, allowing a public IP, blocking a
host that *resolves* to a private IP (rebinding scenario), and that the feature is
disabled by default.

## Enabling (not recommended for untrusted environments)

Set `PHISHLAB_ENABLE_NETWORK_LOOKUPS=true` only after reviewing this document and the
threat model. It remains unimplemented in v1; implementing live fetches is milestone M10
and must preserve every control above.
