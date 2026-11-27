# Indicator analysis

Indicators are extracted statically from the parsed headers and bodies. No URL is resolved
or fetched during extraction. Each indicator keeps its source location so a finding can
point back at where it came from.

## What gets extracted

- URLs (`http`/`https`), with a component breakdown (scheme, userinfo, host, port, path,
  query, fragment).
- Domains, from both URLs and email addresses, normalized to lower case.
- IPv4 and IPv6 addresses, validated.
- Email addresses.
- Attachment metadata (see [detection-rules.md](detection-rules.md) and the attachments
  module).

## Normalization and flags

Each indicator carries `value`, `normalized`, `defanged`, `source`, and `flags`. The flags
are where the interesting signals show up:

- `ip-based-url`: the URL host is a bare IP literal.
- `url-userinfo`: a `user@host` form that can hide the real host.
- `unusual-port:N`: a port other than 80 or 443.
- `punycode-idn`: a label begins with `xn--`, and the decoded form is added as
  `idn-decoded:<unicode>`.
- `non-ascii-domain`: raw non-ASCII characters in the domain.
- `zero-width-char`: zero-width or BOM characters inside a domain, a classic obfuscation.

## Defanging

Every indicator is defanged for display and reporting:

```
https://evil.example.com/login  ->  hxxps://evil[.]example[.]com/login
user@example.com                ->  user[@]example[.]com
198.51.100.9                    ->  198[.]51[.]100[.]9
```

`refang()` reverses the common patterns, but it is used only for controlled internal
processing, for example if the opt-in redirect module is ever enabled. URLs are never made
clickable by default anywhere in the product.

## DoS and ReDoS safety

Per-field scan length is capped (`PHISHLAB_MAX_FIELD_SCAN_BYTES`, default 1 MB), and the
regexes are bounded to avoid catastrophic backtracking.

## Tests

`tests/test_parser_indicators.py` covers URL/IP/port extraction, punycode flagging, the
defang round-trip, IP-literal breakdown, and the scan cap.
