# PhishLab Demo: investigating a phishing email

A walkthrough of PhishLab analyzing a synthetic phishing email end to end. Everything
here runs offline. The sample is `backend/samples/corpus/00_flagship_bank_phish.eml`
(100% synthetic, RFC-2606 reserved domains).

## The sample

A fake bank email engineered to contain every signal PhishLab looks for:

- Fake bank sender: `SecureBank Support <no-reply@secure-bank.example.net>`
- Mismatched Reply-To: `recovery@bank-security-team.invalid`
- Failed authentication: `spf=fail dkim=fail dmarc=fail` (sender-reported)
- Punycode / IDN credential-harvesting URL
- Urgency + credential-request language
- A double-extension executable attachment: `Account_Statement.pdf.exe`

## 1. Import

Drag the `.eml` into **New investigation**, or:

```bash
curl -F "file=@backend/samples/corpus/00_flagship_bank_phish.eml" \
  http://127.0.0.1:8000/api/cases
```

PhishLab hashes the raw bytes, parses headers + MIME defensively, extracts and defangs
indicators, and inspects attachment metadata without ever executing anything.

## 2. Findings (evidence first)

Static analysis produces **13 evidence-linked findings**. Severity (impact if true) and
confidence (how sure we are) are reported separately.

| Rule | Severity | Confidence | Evidence |
|---|---|---|---|
| PL-SENDER-002 Reply-To differs from From | high | high | From=secure-bank.example.net Reply-To=bank-security-team.invalid |
| PL-SENDER-003 Return-Path differs from From | medium | medium | Return-Path=mailer.invalid |
| PL-SENDER-001 Display-name impersonation | medium | low | "SecureBank Support" vs secure-bank.example.net |
| PL-AUTH-001 SPF fail (sender-reported) | high | medium | spf=fail |
| PL-AUTH-002 DKIM fail (sender-reported) | high | medium | dkim=fail |
| PL-AUTH-003 DMARC fail (sender-reported) | high | medium | dmarc=fail |
| PL-URL-002 Punycode / IDN domain | high | high | hxxps://xn--securebank-9db[.]example[.]test/login/verify-account |
| PL-URL-006 Credential/login path | medium | low | /login/verify-account |
| PL-CONTENT-001 Urgency language | low | medium | "URGENT" |
| PL-CONTENT-002 Credential request | medium | medium | "verify your identity" |
| PL-ATT-001 Double extension | high | high | Account_Statement.pdf.exe |
| PL-ATT-002 Dangerous extension | high | medium | .exe (SHA-256 recorded) |
| PL-ATT-004 Executable magic bytes | high | high | PE (MZ) header despite .pdf name |

The URL is shown **defanged** and is never clickable:
`hxxps://xn--securebank-9db[.]example[.]test/login/verify-account`
(decoded IDN: `süecurebank.example.test`).

## 3. Disposition and report

The analyst records a disposition (`malicious`) with a rationale, then exports:

```bash
# JSON (versioned schema v1.0) or PDF, URLs defanged, emails redacted by default
curl "http://127.0.0.1:8000/api/cases/<id>/report.pdf?redact=true" -o report.pdf
```

The report distinguishes observed evidence, heuristic findings, and analyst conclusions,
and lists limitations (for example: authentication results are sender-reported, not
cryptographically verified).

## Safety during the whole flow

- No outbound network calls. No telemetry.
- The attachment is never executed; only metadata (name, MIME, magic bytes, size,
  SHA-256) is inspected.
- The HTML body is shown as sanitized source, never rendered. No remote images or scripts.
