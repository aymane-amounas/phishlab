# Security Policy

PhishLab processes **hostile input** (suspicious emails) by design. Security is the
primary product requirement, not an afterthought.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository, or email the maintainer.
Do not open public issues for exploitable vulnerabilities. Expect an acknowledgement
within a few days.

## Security model (summary)

- **Offline by default.** Static analysis makes zero outbound network calls. No
  telemetry, no third-party APIs, no remote resource loading.
- **Attachments are never executed.** Only static metadata (name, declared MIME,
  magic bytes, size, SHA-256, extension analysis) is inspected.
- **Untrusted HTML is never rendered.** Email bodies are shown as sanitized text or
  escaped source. No remote images, no scripts, no `javascript:`/`data:` execution.
- **Extracted URLs are never auto-opened** and are defanged (`hxxp`, `[.]`) by default.
- **Email content is data, never instructions.** Parsed content cannot influence
  application behavior.
- **Network lookups (redirect inspection) are opt-in and disabled by default.** The
  subsystem is treated as SSRF-sensitive: private/loopback/link-local/reserved
  destinations are rejected, redirects are revalidated, response size and time are
  bounded, cookies/credentials are never forwarded. Not shipped enabled in v1.

See [docs/threat-model.md](docs/threat-model.md) and
[docs/security-model.md](docs/security-model.md) for the full analysis.

## Dependency hygiene

Runtime dependencies (fastapi, uvicorn, reportlab, pydantic, python-multipart) are audited
with `pip-audit` and are clean. The React frontend is a **build-time** concern only: the
shipped artifact is static `dist/` served by FastAPI, and `vite`/`esbuild` never run in
production. `esbuild` is pinned via an `overrides` entry to a patched release. Remaining
`npm audit` advisories apply to the vite dev server (`npm run dev`) alone, which binds to
localhost; they do not reach the deployed application. Upgrading past the vite 5.x line is
a breaking change deferred until the toolchain is revalidated.

## Supported versions

v1.x receives security fixes. This is a portfolio/defensive-research project; run it
local-only and do not expose it to untrusted networks.
