# Architecture

PhishLab is a modular, local-first application: a Python analysis engine behind a FastAPI
HTTP API, a React/Vite workbench on the front, and SQLite for case persistence.

## Components

Each directory under `backend/phishlab/` is its own module with a single job.

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

The modules are import-isolated on purpose. `parser` does not know `cases` exists,
`detection` consumes parser and indicator output and emits findings, and `reporting`
consumes a case. The point is to keep the security-sensitive parsing and extraction code
free of any storage or transport concerns, so there is less surface for a mistake to
cross between layers.

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

The network module is not in that default path. It runs only when an operator enables it
and explicitly asks for a lookup on a specific URL.

## Key decisions

These are the architecture decisions I made and why, kept short.

ADR-001, Python stdlib `email` over a custom parser. It is mature, pure-Python so
memory-safe, and it already handles malformed input through its lax policy. Writing my own
hostile-input parser, or pulling in a heavy dependency to do it, both looked worse than
leaning on the standard library.

ADR-002, evidence-first detection with no single opaque score. Each finding is a discrete,
explainable rule with its own severity and its own confidence. The overall assessment is
an aggregation the UI explains, not a black box.

ADR-003, SQLite, local-only. Zero-config, offline, file-backed, and good enough for a
single-analyst workbench. It has migrations and indexes, and it is swappable later if that
changes.

ADR-004, the network module is isolated and default-off. The SSRF risk is high enough that
static analysis has to be fully useful without it.

ADR-005, severity is not confidence. Severity is the potential impact if the signal is
true; confidence is how sure I am the signal is real. They are reported separately so one
does not quietly stand in for the other.

## Deployment

Docker Compose runs the API (uvicorn) and serves the built frontend from the API's static
mount in a single container, or from a separate nginx container. It binds to `127.0.0.1`
by default. See [deployment.md](deployment.md).
