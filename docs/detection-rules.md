# Detection Rules & Methodology

PhishLab's engine is transparent by design. There is no single opaque phishing score.
Each rule produces a discrete `Finding` with its own evidence and two independent axes.

## Severity vs confidence

- **Severity** = potential impact *if the signal is true*: `informational < low < medium
  < high < critical`.
- **Confidence** = how certain we are the observation is real/meaningful: `low < medium
  < high`.

They are reported separately. A reported SPF failure is high *severity* but medium
*confidence*, because the result is sender-reported and not independently verified. A
display-name heuristic may be medium severity but low confidence.

## The overall assessment

`assessment.summary` aggregates the findings (counts per severity, highest severity). It
is explained in the UI and report as an aggregation of the listed findings, never a
black box. An analyst makes the final disposition.

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

Every finding carries: `rule_id`, `title`, `category`, `severity`, `confidence`,
`evidence` (the concrete matched value), `explanation`, `location` (source), and
`recommendation`.

## False-positive discipline

- A single weak signal does not make an email "malicious". The engine surfaces evidence;
  it does not declare verdicts.
- Return-Path/Reply-To mismatches are common with legitimate ESPs and mailing lists;
  flagged at medium with a note to correlate with authentication alignment.
- Content heuristics (urgency, payment) are low/medium confidence by design.

## Limitations

- Authentication results are parsed from the sender-supplied `Authentication-Results`
  header. PhishLab does not perform cryptographic SPF/DKIM/DMARC verification in v1.
- Content rules are keyword-based and language-limited (English lexicon in v1).
- Lookalike detection is heuristic (punycode/IDN, Unicode), not a brand database.
