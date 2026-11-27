# Network safety (SSRF model)

The optional redirect-inspection module is the highest-risk surface in the whole project.
It is disabled by default (`PHISHLAB_ENABLE_NETWORK_LOOKUPS=false`), and v1 does not
perform live fetches at all. What actually exists and is reused is the safe-destination
guard, which is fully tested.

## Why this is dangerous

A defensive tool that follows attacker-supplied URLs can be turned into a Server-Side
Request Forgery primitive. The attacker gets your server to make requests on their behalf:
cloud metadata at `169.254.169.254`, internal admin panels, `localhost`. That is the
entire reason this module is not on by default.

## Controls

These are enforced in `phishlab/network`:

- Scheme allowlist: only `http` and `https` pass (`check_scheme`). `file`, `gopher`,
  `data`, and the rest are rejected.
- Destination validation (`check_destination`): the host is resolved and every resolved
  IP is checked. Blocked ranges are private, loopback, link-local (including
  `169.254.0.0/16`), multicast, reserved, unspecified, and the IPv4-mapped IPv6 form of
  any of those.
- DNS-rebinding defense: validation happens on the resolved IPs, and a real
  implementation has to re-validate the actually connected peer IP before sending the
  request. That requirement is documented in the code.
- Redirect cap: `MAX_REDIRECTS=5`, with each hop re-validated from scratch.
- Response caps: `MAX_RESPONSE_BYTES=256 KB`, `CONNECT_TIMEOUT=5s`, `TOTAL_TIMEOUT=15s`.
- No credentials: cookies and authorization are never forwarded, bodies are never
  executed, and there is no arbitrary proxy driven by untrusted input.

## Current behaviour

`inspect_redirects()` raises `NetworkDisabled` unless the feature is explicitly enabled,
and `NotImplementedError` (deferred to M10) even when it is. The guard functions
(`check_scheme`, `check_destination`) are fully implemented and unit-tested either way, so
the safe core exists even though the fetch does not.

## Tests

`tests/test_cases_network.py` verifies the scheme allowlist, blocking of
private/loopback/link-local/`169.254.169.254`/`::1`, allowing a public IP, blocking a host
that resolves to a private IP (the rebinding scenario), and that the feature is disabled by
default.

## Enabling it

Set `PHISHLAB_ENABLE_NETWORK_LOOKUPS=true` only after reading this document and the threat
model, and not in an untrusted environment. It stays unimplemented in v1; implementing the
live fetches is milestone M10, and whoever does it has to preserve every control above.
