# Email Parsing

PhishLab parses with the Python standard-library `email` package under the lax
(`compat32`) policy. This is a mature, pure-Python, memory-safe parser that tolerates
malformed input instead of raising.

## What is parsed

- All headers, preserving **order and duplicates**, each kept as both the original raw
  representation and a decoded value (`Header.raw` / `Header.decoded`).
- Convenience fields: From, To, Reply-To, Return-Path, Subject, Date, Message-ID.
- All `Received` headers (in order).
- `Authentication-Results` and `Received-SPF` (parsed as sender-reported, see below).
- Full MIME tree: content type, transfer encoding, charset, filename, disposition, size,
  and nesting depth per part.
- Text bodies decoded safely; HTML kept as **source only** (never rendered).
- Attachments collected with raw payload for static hashing/inspection.

## Defensive handling

- **Never raises on content.** Top-level and per-part failures are captured in
  `ParsedEmail.warnings`.
- **Depth cap** (`PHISHLAB_MAX_MIME_DEPTH`, default 20) and **part cap**
  (`PHISHLAB_MAX_MIME_PARTS`, default 200) defend against nesting/part-count DoS.
- Encoded words and internationalized headers are decoded for display; the original line
  is retained for evidence.
- Malformed headers (missing colons, bad encodings) yield a best-effort parse plus a
  warning, demonstrated by `samples/corpus/10_malformed_headers.eml`.
- Empty input yields a warning, not a crash (`11_empty.eml`).

## Authentication results are sender-reported

`AuthResults.verified` is **always `False`** in v1. PhishLab reads the mechanism results
(`spf`, `dkim`, `dmarc`) from the `Authentication-Results` header the sending/receiving
infrastructure supplied. It does **not** cryptographically verify them. The UI and
reports label these explicitly as "sender-reported". This is a deliberate honesty
constraint: an email containing `dkim=pass` is not proof of a valid signature.

## Tests

See `tests/test_parser_indicators.py` for header extraction, sender-reported auth,
malformed/empty handling, nested multipart, and the field-scan cap.
