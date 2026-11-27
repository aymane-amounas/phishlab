# Report schema (v1.0)

JSON reports come out of `phishlab.reporting.build_json_report`, and the shape is
versioned through `schema_version`.

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

## What the schema guarantees

All URLs appear defanged, in the `defanged` field. The raw `value` is kept for evidence
but is never clickable. With `redacted: true` (the default) the email addresses in sender
fields and analyst notes are replaced with `[redacted-email]`. `authentication.verified`
is always `false` in v1, for the reasons in [email-parsing.md](email-parsing.md). And
`caveats` always lists the interpretation limits, so a consumer cannot read the findings
without also seeing what they do not mean.

## Endpoints

- `GET /api/cases/{id}/report.json?redact=true|false`
- `GET /api/cases/{id}/report.pdf?redact=true|false`

The PDF mirrors this content with an executive summary, a sender/auth table, the findings
(severity-colored, with evidence and confidence), defanged indicators, and the caveats.

## Versioning

Any backward-incompatible change bumps `schema_version`, so a consumer should check it
before parsing.
