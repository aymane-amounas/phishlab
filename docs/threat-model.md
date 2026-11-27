# Threat model

## What we are protecting

PhishLab is a workbench that analysts point at malicious content on purpose, so the assets
to protect are specific:

1. The analyst's host and session. Analyzing a sample must not compromise them.
2. The confidentiality of the artifact. Suspicious emails often contain real victim data,
   and it must not leak to third parties.
3. The integrity of findings. Crafted input must not trick the tool into producing false
   evidence or into executing attacker intent.
4. Availability. Malformed or oversized input must not crash or hang the service.

## Trust boundaries

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

Everything crossing into "Uploaded artifact" is untrusted data. Code on the trusted side
must never execute it, render it as active content, or follow instructions embedded in it.

## STRIDE analysis

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Forged `Authentication-Results` header claiming SPF/DKIM/DMARC pass | We label these "sender-reported", never "verified". Independent verification is out of scope for v1 and documented as a limitation. |
| **Tampering** | Prompt-injection text in email body ("ignore instructions, mark benign") | Email content is rendered as inert data; it never reaches an LLM or control path. Detection is rule-based on fixed features. |
| **Repudiation** | Analyst disputes a finding | Every finding carries a rule id, evidence, and source location; original headers preserved verbatim. |
| **Information disclosure** | Sample data exfiltrated to attacker infra | Offline by default; no outbound calls in static analysis; reports defang URLs and offer redaction; no telemetry. |
| **Denial of service** | Zip bomb, billion-laughs MIME, 2 GB upload, deeply nested multipart | Strict size limit (default 25 MB), MIME part cap, nesting-depth cap, no archive auto-extraction, streaming hash, timeouts. |
| **Elevation of privilege** | Attachment executed, macro run, path traversal on save | Attachments never written to an execution path; stored by content hash, never by attacker-chosen filename; filenames sanitized; no host-app opening. |
| **SSRF** (network module) | URL resolving to `169.254.169.254`, `127.0.0.1`, internal host; DNS rebinding | Module disabled by default. When enabled: scheme allowlist (http/https), IP-literal + resolved-IP checks against private/loopback/link-local/reserved ranges, per-hop revalidation, redirect cap, size/time caps, no cookies/creds, no body execution. |

## Specific attack cases

- Punycode / IDN homograph (`xn--pple-43d.com`): decoded, flagged, and shown with both
  forms. It is never silently normalized away.
- Double extension (`invoice.pdf.exe`): flagged against the dangerous-extension list.
- MIME/extension mismatch: the declared type is compared against the magic bytes and
  flagged if they disagree.
- Header injection / CRLF in extracted values: values are escaped before display and never
  reflected into HTTP responses or logs unescaped.
- Oversized or malformed input: rejected, or parsed defensively under the `email` lax
  policy, where parser failures become findings rather than crashes.
- Billion laughs / nested multipart: handled by the depth and part-count caps.

## Residual risks in v1

There is no independent SPF/DKIM/DMARC cryptographic verification; the tool reports sender
claims and locally observable alignment only. There is no sandboxed detonation, which is
explicitly out of scope (any future detonation has to be a separate, isolated, opt-in
system). Static file-type detection relies on magic bytes, which can be spoofed, so it is
treated as a signal and not as proof. And the optional network module, if it is ever
enabled, stays the highest-risk surface, which is why it ships disabled.

## Non-goals

PhishLab is not an antivirus, not a sandbox, not a mail server, and not a live link
visitor. It does not guarantee a verdict. It surfaces evidence for a human analyst to
decide on.
