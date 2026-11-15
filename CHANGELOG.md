# Changelog

All notable changes to PhishLab are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/). Versioning: SemVer.

## [1.0.0] - 2026-11-15

### Added
- M0: repository foundation, threat model, security model, architecture docs.
- M1: artifact ingestion + stdlib-based MIME/email parser (defensive, depth/part caps).
- M2: indicator extraction (URLs, domains, IPv4/IPv6, emails), punycode/IDN detection,
  URL defanging and component breakdown.
- M3: transparent rule-based detection engine (19 rules; severity independent from
  confidence; evidence-linked findings).
- M4: SQLite case storage with migrations, indexes, notes, disposition, search, retention.
- M5: React/Vite investigation workbench (dashboard, new investigation, case tabs).
- M6: versioned JSON report schema (v1.0) and PDF reports (defanged, redaction option).
- M7: 39 automated tests including SSRF guards, path traversal, injection inertness,
  oversized input, and response security headers.
- M8: multi-stage Docker image + hardened docker-compose (localhost-only, non-root,
  read-only rootfs); build/run/persistence validated.
- Synthetic `.eml` corpus incl. a flagship bank-phishing demonstration sample.
- SSRF-safe network module (disabled by default; guards implemented and tested).

### Deferred
- M10: live redirect inspection (ships disabled; guards present, no network fetch in v1).
- CI workflows staged in `.github-pending/` pending a `workflow`-scoped token.
