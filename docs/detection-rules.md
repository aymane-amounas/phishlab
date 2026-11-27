# Detection rules and methodology

The engine is transparent by design. There is no single opaque phishing score. Each rule
produces a discrete `Finding` with its own evidence and two independent axes.

## Severity versus confidence

Severity is the potential impact if the signal is true:
`informational < low < medium < high < critical`. Confidence is how certain the tool is
that the observation is real and meaningful: `low < medium < high`.

They are kept separate because they answer different questions. A reported SPF failure is
high severity but only medium confidence, because the result is sender-reported and not
independently verified. A display-name heuristic might be medium severity but low
confidence. Collapsing those into one number would hide exactly the thing an analyst needs
to see.

## The overall assessment

`assessment.summary` aggregates the findings (counts per severity, and the highest
severity present). The UI and the report present it as an aggregation of the listed
findings, never as a black box. The analyst still makes the final disposition.

## Rule catalogue

| Rule | Category | Severity | Confidence | Signal |
|---|---|---|---|---|
| PL-SENDER-001 | sender | medium | low | Display name references a brand not matching the From domain |
| PL-SENDER-002 | sender | high | high | Reply-To domain differs from From domain |
| PL-SENDER-003 | sender | medium | medium | Return-Path domain differs from From domain |
| PL-AUTH-001 | authentication | high/medium | medium | SPF fail / softfail (sender-reported) |
| PL-AUTH-002 | authentication | high/medium | medium | DKIM fail / softfail (sender-reported) |
| PL-AUTH-003 | authentication | high/medium | medium | DMARC fail / softfail (sender-reported) |
| PL-AUTH-004 | authentication | informational | high | No authentication evidence present |
| PL-URL-001 | url | high | high | URL points to a bare IP address |
| PL-URL-002 | url | high | high | Punycode / IDN domain |
| PL-URL-003 | url | medium | high | URL userinfo before host |
| PL-URL-004 | url | low | medium | Unusual port |
| PL-URL-005 | url | medium | medium | Known link shortener |
| PL-URL-006 | url | medium | low | Path suggests a credential/login page |
| PL-CONTENT-001 | content | low | medium | Urgency / pressure language |
| PL-CONTENT-002 | content | medium | medium | Credential / verification request |
| PL-CONTENT-003 | content | medium | low | Payment / financial request |
| PL-ATT-001 | attachment | high | high | Double extension (e.g. `.pdf.exe`) |
| PL-ATT-002 | attachment | high | medium | Dangerous/executable extension |
| PL-ATT-003 | attachment | medium | high | Extension/magic-byte mismatch |
| PL-ATT-004 | attachment | high | high | Magic bytes are executable content |

Every finding carries `rule_id`, `title`, `category`, `severity`, `confidence`,
`evidence` (the concrete matched value), `explanation`, `location` (the source), and
`recommendation`.

## Keeping false positives in check

A single weak signal does not make an email "malicious". The engine surfaces evidence; it
does not hand down verdicts. Return-Path and Reply-To mismatches, for instance, are common
with legitimate ESPs and mailing lists, so they are flagged at medium with a note to
correlate against authentication alignment. The content heuristics (urgency, payment) are
deliberately low or medium confidence.

## Limitations

Authentication results are parsed from the sender-supplied `Authentication-Results`
header; PhishLab does not do cryptographic SPF/DKIM/DMARC verification in v1. The content
rules are keyword-based and limited to an English lexicon in v1. Lookalike detection is
heuristic (punycode/IDN and Unicode), not a brand database.
