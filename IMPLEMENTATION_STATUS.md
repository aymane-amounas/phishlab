# Implementation Status

Tracks what is actually built and tested vs deferred. Honest status, not aspirational.

Legend: ✅ done & tested · 🟡 partial · ⬜ not started · 🚫 deferred by design

| Milestone | Status | Notes |
|---|---|---|
| M0 Repo foundation + threat model | 🟡 | Governance docs, threat model, security model written |
| M1 Ingestion + MIME parser | ⬜ | |
| M2 Indicator extraction + defanging | ⬜ | |
| M3 Static detection rules | ⬜ | |
| M4 Case storage + workflow | ⬜ | |
| M5 Frontend workbench | ⬜ | |
| M6 JSON/PDF reporting | ⬜ | |
| M7 Security testing + hardening | ⬜ | |
| M8 Docker + offline validation | ⬜ | |
| M9 CI + publication | ⬜ | `workflow` token scope unavailable on active account; CI staged in `.github-pending/` |
| M10 Controlled URL inspection | 🚫 | Deferred: ships disabled; enable only after SSRF controls reviewed |

## Known constraints
- Active `gh` account (`aymane-amounas`) token lacks the `workflow` scope, so
  `.github/workflows/*` cannot be pushed from here. CI lives in `.github-pending/` with
  activation instructions in `docs/deployment.md`.
