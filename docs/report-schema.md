# Report Schema (v1.0)

JSON reports are produced by `phishlab.reporting.build_json_report`. The schema is
versioned via `schema_version`.

## Top-level shape

```json
{
  "schema_version": "1.0",
  "generated_at": "<ISO-8601 UTC>",
  "redacted": true,
  "case": {
    "id": "<uuid>",
    "created_at": "<ISO-8601>",
    "disposition": "undetermined|benign|suspicious|malicious|inconclusive",
    "rationale": "<string|null>",
    "analyst_notes": "<string|null>"
  },
  "artifact": { "sha256": "<hex>", "size": 0, "source_kind": "eml|headers|text", "declared_filename": "<string|null>" },
  "sender_analysis": { "from": "...", "to": "...", "reply_to": "...", "return_path": "...", "subject": "...", "date": "...", "message_id": "..." },
  "authentication": { "raw": "...", "spf": "fail|pass|...|null", "dkim": "...", "dmarc": "...", "verified": false },
  "indicators": {
    "urls":   [ { "type": "url", "value": "...", "normalized": "...", "defanged": "hxxps://...", "source": "...", "flags": ["..."] } ],
    "domains":[ ... ], "ipv4": [ ... ], "ipv6": [ ... ], "emails": [ ... ]
  },
  "attachments": [ { "filename": "...", "declared_mime": "...", "detected_type": "...", "size": 0, "sha256": "<hex>", "extensions": ["..."], "flags": ["..."] } ],
  "findings": [ {
    "rule_id": "PL-URL-002", "title": "...", "category": "url",
    "severity": "informational|low|medium|high|critical",
    "confidence": "low|medium|high",
    "evidence": "...", "explanation": "...", "location": "...", "recommendation": "..."
  } ],
  "assessment": { "counts": { "critical":0,"high":0,"medium":0,"low":0,"informational":0 }, "highest_severity": "high", "summary": "..." },
  "warnings": [ "..." ],
  "caveats": [ "Authentication results are sender-reported ...", "..." ]
}
```

## Guarantees

- All URLs appear **defanged** (`defanged` field; raw `value` is retained for evidence
  but is never clickable).
- `redacted: true` (default) replaces email addresses in sender fields and analyst notes
  with `[redacted-email]`.
- `authentication.verified` is always `false` in v1.
- `caveats` always lists the interpretation limits.

## Endpoints

- `GET /api/cases/{id}/report.json?redact=true|false`
- `GET /api/cases/{id}/report.pdf?redact=true|false`

The PDF mirrors this content with an executive summary, sender/auth table, findings
(severity-colored, with evidence and confidence), defanged indicators, and caveats.

## Versioning

Backward-incompatible changes bump `schema_version`. Consumers should check it before
parsing.
