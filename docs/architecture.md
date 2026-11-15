# Architecture

PhishLab is a modular, local-first application: a Python analysis engine behind a FastAPI
HTTP API, a React/Vite workbench frontend, and SQLite for case persistence.

## Components (independent modules)

```
backend/phishlab/
  ingestion/     Validate, size-limit, hash, store raw artifact
  parser/        Email + MIME parsing (stdlib email, lax policy)
  indicators/    URL/domain/IP/email/attachment extraction + normalization
  defang/        Defang / refang, URL component breakdown
  attachments/   Static metadata only (name, MIME, magic bytes, size, SHA-256)
  detection/     Transparent rule engine -> findings (evidence-linked)
  cases/         SQLite persistence, migrations, retention
  reporting/     JSON (versioned schema) + PDF generation
  network/       Opt-in SSRF-safe redirect inspection (DISABLED by default)
  api/           FastAPI routes
```

Each module is import-isolated: `parser` does not know about `cases`; `detection`
consumes parser+indicator outputs and emits findings; `reporting` consumes a case. This
keeps the security-sensitive parsing/extraction code free of storage/transport concerns.

## Data flow

```
.eml / headers / text
        │
   ingestion  ──► raw bytes + SHA-256 + size + content-type
        │
     parser   ──► headers (raw + decoded), MIME tree, auth results (sender-reported)
        │
  indicators  ──► URLs, domains, IPv4/IPv6, emails, attachments (each w/ source location)
        │
  attachments ──► per-part static metadata + static findings
        │
   detection  ──► findings[] { rule_id, severity, confidence, evidence, location, recommendation }
        │
     cases     ──► persisted Case { artifact, parsed, indicators, findings, notes, disposition }
        │
   reporting  ──► JSON (schema v1) / PDF (defanged)
```

The network module is **not** in the default path. It is invoked only when an operator
enables it and explicitly initiates a lookup for a specific URL.

## Key architectural decisions (ADRs, abbreviated)

- **ADR-001 Python stdlib `email` over a custom parser.** It is mature, memory-safe
  (pure Python), handles malformed input via lax policy, and avoids reinventing a
  hostile-input parser. Chosen over writing our own or pulling a heavy dependency.
- **ADR-002 Evidence-first detection, no single opaque score.** Each finding is a
  discrete, explainable rule with its own severity and *independent* confidence. The
  "overall assessment" is an aggregation the UI explains, not a black box.
- **ADR-003 SQLite, local-only.** Zero-config, offline, file-backed, good enough for a
  single-analyst workbench. Migrations + indexes included; swappable later.
- **ADR-004 Network module isolated and default-off.** SSRF risk is high enough that
  static analysis must be fully useful without it.
- **ADR-005 Severity ≠ confidence.** Severity = potential impact if true; confidence =
  how sure we are the signal is real. Reported separately.

## Deployment

Docker Compose runs the API (uvicorn) and serves the built frontend via the API's static
mount (single container) or a separate nginx container. Binds to `127.0.0.1` by default.
See [deployment.md](deployment.md).
