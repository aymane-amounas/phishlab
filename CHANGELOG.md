# Changelog

Notable changes to PhishLab. The format follows
[Keep a Changelog](https://keepachangelog.com/) and versions follow SemVer.

## [Unreleased]

### Added
- Project logo in the README banner and the web UI favicon/sidebar, plus a terminal
  startup banner.
- GitHub Actions CI is now live (`.github/workflows/ci.yml`), running the backend tests,
  ruff, and a secret scan.

### Changed
- Relicensed to the Aymane Amounas Noncommercial Attribution License 1.0 (was MIT) and
  added NOTICE. Earlier MIT-tagged releases stay under their original terms.
- The backend now serves the full built UI, including `/logo.png`, from the API.
- Hardened the email parser against hostile input (a malformed URL port in a message body
  could previously crash analysis) and audited dependencies. The backend test suite is now
  at 62 tests.

## [1.0.0] - 2026-11-15

### Added
- M0: repository foundation, threat model, security model, architecture docs.
- M1: artifact ingestion and an stdlib-based MIME/email parser, written defensively with
  depth and part caps.
- M2: indicator extraction (URLs, domains, IPv4/IPv6, emails), punycode/IDN detection,
  and URL defanging with a component breakdown.
- M3: a transparent rule-based detection engine (20 rules, with confidence tracked
  independently from severity and every finding linked to its evidence).
- M4: SQLite case storage with migrations, indexes, notes, disposition, search, and
  retention.
- M5: a React/Vite investigation workbench (dashboard, new investigation, case tabs).
- M6: a versioned JSON report schema (v1.0) and PDF reports, defanged, with a redaction
  option.
- M7: 39 automated tests covering SSRF guards, path traversal, injection inertness,
  oversized input, and response security headers.
- M8: a multi-stage Docker image and a hardened docker-compose setup (localhost-only,
  non-root, read-only rootfs), with build, run, and persistence validated.
- A synthetic `.eml` corpus including the flagship bank-phishing demonstration sample.
- The SSRF-safe network module, disabled by default, with guards implemented and tested.

### Deferred
- M10: live redirect inspection. It ships disabled; the guards are present but there is no
  network fetch in v1.
