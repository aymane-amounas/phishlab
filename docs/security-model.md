# Security model

The rule everything else follows: treat every uploaded artifact as hostile, and treat its
content as data that must never influence control flow.

## Defense layers

### Ingestion

There is a file-type allowlist (`.eml`, `message/rfc822`, raw text) and a hard size limit
(default 25 MB, configurable via `PHISHLAB_MAX_UPLOAD_BYTES`). The SHA-256 is recorded on
the raw bytes before any parsing happens. The artifact is stored in a temp location keyed
by its content hash and cleaned per the retention policy, and the raw bytes are preserved
verbatim as evidence.

### Parsing

The Python stdlib `email` parser runs under the lax (`compat32`) policy, so malformed
input produces a best-effort tree instead of an exception, and failures become findings.
MIME nesting depth is capped (default 20) and part count is capped (default 200). No
archive is auto-extracted, no attachment is written to an executable path or opened with a
host application. Encoded words and internationalized headers are decoded for display while
the original header line is preserved alongside the decoded value.

### Indicator extraction

URLs, domains, IPs, and emails are extracted with bounded regex (no catastrophic
backtracking, with input length capped per field). No URL is resolved or fetched during
extraction. Punycode and IDN are decoded and flagged, and suspicious Unicode (mixed
scripts, zero-width characters, confusables) is detected.

### Output and rendering

Email bodies are returned as sanitized text or escaped source. HTML is never rendered as
active content, so no remote images, no scripts, no external CSS. URLs are defanged by
default everywhere, in the UI and in reports. Every extracted string is output-encoded, and
nothing untrusted is reflected into logs, headers, or responses unescaped.

### Storage

SQLite with parameterized queries only, never string-built SQL. The original evidence is
stored separately from analyst-added conclusions. There are retention and deletion
controls, and logging is kept safe (no raw bodies or credentials in logs).

### Network (opt-in, disabled by default)

See [network-safety.md](network-safety.md). It is treated as an SSRF-sensitive subsystem:
scheme allowlist, pre-connect and post-resolution IP range checks, per-redirect
revalidation, DNS-rebinding defense, redirect/size/time caps, and no cookies or
credentials.

## Prompt-injection stance

Email bodies routinely carry instructions aimed at a reader or at an automated system
("reply with your password", or, against tooling, "ignore previous instructions"). In
PhishLab that body content is inert. It is never passed to a model, a shell, an eval, or
any control path. Detection runs on a fixed, enumerated set of features, so attacker text
cannot change the verdict logic even in principle.

## What PhishLab deliberately does not do

It does not execute, detonate, or sandbox-run anything. It does not visit suspicious links
in a real browser. It does not call third-party reputation services unless an operator
explicitly enables and configures a lookup, which is not shipped enabled in v1. And it does
not claim cryptographic verification of SPF/DKIM/DMARC that it did not actually perform.
