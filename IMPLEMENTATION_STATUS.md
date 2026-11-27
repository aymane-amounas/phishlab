# Implementation Status

What is actually built and tested versus what is deferred. I keep this honest rather than
aspirational, so the status column below means what it says: done is done and tested,
partial is half-there, deferred is a deliberate not-yet.

| Milestone | Status | Notes |
|---|---|---|
| M0 Repo foundation + threat model | done | Governance docs, threat model, security model, architecture |
| M1 Ingestion + MIME parser | done | stdlib `email` lax policy, depth/part caps, defensive, tested |
| M2 Indicator extraction + defanging | done | URLs/domains/IPs/emails, punycode/IDN, defang + breakdown, tested |
| M3 Static detection rules | done | 20 evidence-linked rules, severity and confidence tracked separately, tested |
| M4 Case storage + workflow | done | SQLite, migrations, indexes, notes/disposition, search, retention |
| M5 Frontend workbench | done | React/Vite dashboard, investigation, case tabs, browser-verified |
| M6 JSON/PDF reporting | done | Versioned JSON schema v1.0 + reportlab PDF, defanged, redaction |
| M7 Security testing + hardening | done | 62 tests including SSRF, path traversal, injection, oversized input, CSP |
| M8 Docker + offline validation | done | Multi-stage image built and run, health + persistence verified |
| M9 CI + publication | done | GitHub Actions CI live (`.github/workflows/ci.yml`), repo published |
| M10 Controlled URL inspection | deferred | Ships disabled, SSRF guards implemented and tested, no live fetch |

Test summary: 62 backend tests passing, `ruff check` and `ruff format` clean, the frontend
builds, and the Docker image builds, runs healthy, and persists across a restart. The
flagship synthetic bank-phish produces 13 evidence-linked findings and a PDF report.

## Known constraints

The one real gap is M10. Live redirect inspection is not implemented in v1: the guard
functions exist and are tested, but `inspect_redirects()` still raises rather than
fetching anything. See `docs/network-safety.md` for why that is deliberate.
