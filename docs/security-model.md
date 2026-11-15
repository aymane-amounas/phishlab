# Security Model

PhishLab's guiding rule: **treat every uploaded artifact as hostile, and treat its
content as data that must never influence control flow.**

## Defense layers

### 1. Ingestion
- File-type allowlist (`.eml`, `message/rfc822`, raw text).
- Hard size limit (default **25 MB**, configurable via `PHISHLAB_MAX_UPLOAD_BYTES`).
- SHA-256 recorded on the raw bytes before any parsing.
- Stored in a temp location keyed by content hash; cleaned per retention policy.
- Raw bytes preserved verbatim for evidence.

### 2. Parsing
- Python stdlib `email` with the lax (`compat32`) policy so malformed input yields a
  best-effort tree instead of an exception; failures are captured as findings.
- MIME nesting depth cap (default 20) and part-count cap (default 200).
- No archive auto-extraction. No attachment is ever written to an executable path or
  opened with a host application.
- Encoded words / internationalized headers decoded for display; the **original header
  line is preserved** alongside the decoded value.

### 3. Indicator extraction
- URLs/domains/IPs/emails extracted with bounded regex (no catastrophic backtracking;
  input length capped per field).
- No URL is resolved or fetched during static extraction.
- Punycode/IDN decoded and flagged; suspicious Unicode (mixed scripts, zero-width,
  confusables) detected.

### 4. Output / rendering
- Email bodies are returned as **sanitized text or escaped source**; HTML is never
  rendered as active content. No remote images, no scripts, no external CSS.
- URLs are **defanged by default** everywhere (UI and reports).
- All extracted strings are output-encoded; nothing untrusted is reflected into logs,
  headers, or responses unescaped.

### 5. Storage
- SQLite with parameterized queries only (no string-built SQL).
- Original evidence stored separately from analyst-added conclusions.
- Retention + deletion controls; safe logging (no raw bodies/credentials in logs).

### 6. Network (opt-in, disabled by default)
See [network-safety.md](network-safety.md). Treated as an SSRF-sensitive subsystem:
scheme allowlist, pre-connect and post-resolution IP range checks, per-redirect
revalidation, DNS-rebinding defense, redirect/size/time caps, no cookies/credentials.

## Prompt-injection stance

Email bodies frequently contain instructions aimed at a reader or an automated system
("reply with your password", or, against tooling, "ignore previous instructions"). In
PhishLab, body content is inert: it is never passed to a model, a shell, an eval, or any
control path. Detection operates on fixed, enumerated features, so attacker text cannot
change the verdict logic.

## What PhishLab deliberately does not do

- Execute, detonate, or sandbox-run anything.
- Visit suspicious links in a real browser.
- Call third-party reputation services unless an operator explicitly enables and
  configures a lookup (not shipped enabled in v1).
- Claim cryptographic verification of SPF/DKIM/DMARC it did not perform.
