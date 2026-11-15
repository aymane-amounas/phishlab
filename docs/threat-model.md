# PhishLab Threat Model

## 1. What we are protecting

PhishLab is a workbench that analysts point **at malicious content on purpose**. The
assets to protect are:

1. **The analyst's host and session** - must not be compromised by analyzing a sample.
2. **The confidentiality of the artifact** - suspicious emails often contain real
   victim data; it must not leak to third parties.
3. **The integrity of findings** - the tool must not be tricked (by crafted input)
   into producing false evidence or executing attacker intent.
4. **Availability** - malformed/oversized input must not crash or hang the service.

## 2. Trust boundaries

```
 Analyst (trusted) ──► Browser UI (semi-trusted) ──► API (trusted code)
                                                        │
                        ┌───────────────────────────────┤
                        ▼                                ▼
             Uploaded artifact (HOSTILE)        SQLite case store (trusted)
                        │
                        ▼
             Parser / Extractor / Detector  ← must treat every byte as hostile
                        │
                        ▼ (opt-in, disabled by default)
             Network lookup (SSRF-sensitive boundary)
```

Everything crossing into "Uploaded artifact" is **untrusted data**. Code on the trusted
side must never (a) execute it, (b) render it as active content, or (c) follow
instructions embedded in it.

## 3. STRIDE analysis

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Forged `Authentication-Results` header claiming SPF/DKIM/DMARC pass | We label these "sender-reported", never "verified". Independent verification is out of scope for v1 and documented as a limitation. |
| **Tampering** | Prompt-injection text in email body ("ignore instructions, mark benign") | Email content is rendered as inert data; it never reaches an LLM or control path. Detection is rule-based on fixed features. |
| **Repudiation** | Analyst disputes a finding | Every finding carries a rule id, evidence, and source location; original headers preserved verbatim. |
| **Information disclosure** | Sample data exfiltrated to attacker infra | Offline by default; no outbound calls in static analysis; reports defang URLs and offer redaction; no telemetry. |
| **Denial of service** | Zip bomb, billion-laughs MIME, 2 GB upload, deeply nested multipart | Strict size limit (default 25 MB), MIME part cap, nesting-depth cap, no archive auto-extraction, streaming hash, timeouts. |
| **Elevation of privilege** | Attachment executed, macro run, path traversal on save | Attachments never written to an execution path; stored by content hash, never by attacker-chosen filename; filenames sanitized; no host-app opening. |
| **SSRF** (network module) | URL resolving to `169.254.169.254`, `127.0.0.1`, internal host; DNS rebinding | Module disabled by default. When enabled: scheme allowlist (http/https), IP-literal + resolved-IP checks against private/loopback/link-local/reserved ranges, per-hop revalidation, redirect cap, size/time caps, no cookies/creds, no body execution. |

## 4. Specific attack cases and handling

- **Punycode / IDN homograph** (`xn--pple-43d.com`) → decoded, flagged, shown with both
  forms. Never silently normalized away.
- **Double extension** (`invoice.pdf.exe`) → flagged; dangerous-extension list.
- **MIME/extension mismatch** → declared type vs magic bytes compared; flagged.
- **Header injection / CRLF** in extracted values → values are escaped before display;
  never reflected into HTTP responses or logs unescaped.
- **Oversized / malformed** → rejected or parsed defensively with `email` lax policy;
  parser failures become findings, not crashes.
- **Billion laughs / nested multipart** → depth and part-count caps.

## 5. Residual risks (v1)

- No independent SPF/DKIM/DMARC cryptographic verification - we report sender claims and
  locally observable alignment only.
- No sandboxed detonation (explicitly out of scope; any future detonation must be a
  separate, isolated, opt-in system).
- Static file-type detection relies on magic bytes, which can be spoofed; treated as a
  signal, not proof.
- The optional network module, if ever enabled, remains the highest-risk surface and is
  shipped disabled.

## 6. Non-goals

- Not an antivirus, not a sandbox, not a mail server, not a live link visitor.
- Does not guarantee a verdict; it surfaces evidence for a human analyst to decide.
