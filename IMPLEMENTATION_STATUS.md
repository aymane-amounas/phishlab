# Implementation Status

Tracks what is actually built and tested vs deferred. Honest status, not aspirational.

Legend: ✅ done & tested · 🟡 partial · ⬜ not started · 🚫 deferred by design

| Milestone | Status | Notes |
|---|---|---|
| M0 Repo foundation + threat model | ✅ | Governance docs, threat model, security model, architecture |
| M1 Ingestion + MIME parser | ✅ | stdlib `email` lax policy; depth/part caps; defensive, tested |
| M2 Indicator extraction + defanging | ✅ | URLs/domains/IPs/emails, punycode/IDN, defang + breakdown, tested |
| M3 Static detection rules | ✅ | 19 evidence-linked rules; severity + independent confidence, tested |
| M4 Case storage + workflow | ✅ | SQLite, migrations, indexes, notes/disposition, search, retention |
| M5 Frontend workbench | ✅ | React/Vite; dashboard, investigation, case tabs; browser-verified |
| M6 JSON/PDF reporting | ✅ | Versioned JSON schema v1.0 + reportlab PDF, defanged, redaction |
| M7 Security testing + hardening | ✅ | 39 tests incl. SSRF, path traversal, injection, oversized, CSP |
| M8 Docker + offline validation | ✅ | Multi-stage image built & run; health + persistence verified |
| M9 CI + publication | 🟡 | CI staged in `.github-pending/` (no `workflow` token scope); repo published |
| M10 Controlled URL inspection | 🚫 | Deferred: ships disabled; SSRF guards implemented + tested, no live fetch |

**Test summary:** 39 backend tests passing; `ruff check`/`ruff format` clean; frontend
builds; Docker image builds, runs healthy, persists across restart. Flagship synthetic
bank-phish produces 13 evidence-linked findings and a PDF report.

## Known constraints
- Active `gh` account (`aymane-amounas`) token lacks the `workflow` scope, so
  `.github/workflows/*` cannot be pushed from here. CI lives in `.github-pending/` with
  activation instructions in `docs/deployment.md`.
