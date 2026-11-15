# Indicator Analysis

Indicators are extracted statically from parsed headers and bodies. **No URL is resolved
or fetched during extraction.** Each indicator keeps its source location for evidence.

## Extracted types

- URLs (`http`/`https`), with component breakdown (scheme, userinfo, host, port, path,
  query, fragment).
- Domains (from URLs and email addresses), normalized lower-case.
- IPv4 and IPv6 addresses (validated).
- Email addresses.
- Attachment metadata (see [detection-rules.md](detection-rules.md) and the attachments
  module).

## Normalization and flags

Each indicator carries `value`, `normalized`, `defanged`, `source`, and `flags`:

- `ip-based-url` - URL host is a bare IP literal.
- `url-userinfo` - `user@host` form that can hide the real host.
- `unusual-port:N` - port other than 80/443.
- `punycode-idn` - a label begins with `xn--`; the decoded form is added as
  `idn-decoded:<unicode>`.
- `non-ascii-domain` - raw non-ASCII characters in the domain.
- `zero-width-char` - zero-width/BOM characters inside a domain (obfuscation).

## Defanging

Defanging is applied to every indicator for display and reporting:

```
https://evil.example.com/login  ->  hxxps://evil[.]example[.]com/login
user@example.com                ->  user[@]example[.]com
198.51.100.9                    ->  198[.]51[.]100[.]9
```

`refang()` reverses common patterns and is used **only** for controlled internal
processing (for example, if the opt-in redirect module is enabled). URLs are never made
clickable by default anywhere in the product.

## DoS and ReDoS safety

- Per-field scan length is capped (`PHISHLAB_MAX_FIELD_SCAN_BYTES`, default 1 MB).
- Regexes are bounded and avoid catastrophic backtracking.

## Tests

`tests/test_parser_indicators.py` covers URL/IP/port extraction, punycode flagging,
defang round-trip, IP-literal breakdown, and the scan cap.
