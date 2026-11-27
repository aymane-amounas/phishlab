# Email parsing

PhishLab parses with the Python standard library's `email` package under the lax
(`compat32`) policy. It is a mature, pure-Python, memory-safe parser that tolerates
malformed input instead of raising, which is exactly what you want when the input is
hostile by assumption.

## What is parsed

- All headers, keeping their order and any duplicates, each stored both as the original
  raw representation and a decoded value (`Header.raw` / `Header.decoded`).
- Convenience fields: From, To, Reply-To, Return-Path, Subject, Date, Message-ID.
- All `Received` headers, in order.
- `Authentication-Results` and `Received-SPF`, parsed as sender-reported (see below).
- The full MIME tree: content type, transfer encoding, charset, filename, disposition,
  size, and nesting depth per part.
- Text bodies, decoded safely. HTML is kept as source only and never rendered.
- Attachments, collected with their raw payload for static hashing and inspection.

## Defensive handling

The parser never raises on content. Top-level and per-part failures are captured in
`ParsedEmail.warnings` rather than thrown. A depth cap (`PHISHLAB_MAX_MIME_DEPTH`, default
20) and a part cap (`PHISHLAB_MAX_MIME_PARTS`, default 200) defend against nesting and
part-count DoS.

Encoded words and internationalized headers are decoded for display, with the original
line retained as evidence. Malformed headers (missing colons, bad encodings) get a
best-effort parse plus a warning, which `samples/corpus/10_malformed_headers.eml`
demonstrates. Empty input yields a warning, not a crash (`11_empty.eml`).

## Authentication results are sender-reported

`AuthResults.verified` is always `False` in v1. PhishLab reads the mechanism results
(`spf`, `dkim`, `dmarc`) straight from the `Authentication-Results` header that the
sending or receiving infrastructure supplied. It does not cryptographically verify them.
The UI and reports label these explicitly as sender-reported. This is a deliberate honesty
constraint: an email that says `dkim=pass` is not proof of a valid signature, and the tool
should not pretend otherwise.

## Tests

See `tests/test_parser_indicators.py` for header extraction, sender-reported auth,
malformed and empty handling, nested multipart, and the field-scan cap.
