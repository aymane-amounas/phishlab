# Security Policy

PhishLab processes hostile input (suspicious emails) by design, so security is the main
product requirement here, not something bolted on afterward.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository, or email the maintainer.
Please do not open public issues for anything exploitable. I will try to acknowledge
within a few days.

## Security model in short

Static analysis is offline by default. It makes zero outbound network calls, with no
telemetry, no third-party APIs, and no remote resource loading.

Attachments are never executed. The tool only looks at static metadata: name, declared
MIME, magic bytes, size, SHA-256, and extension analysis.

Untrusted HTML is never rendered. Email bodies are shown as sanitized text or escaped
source, so there are no remote images, no scripts, and no `javascript:`/`data:`
execution.

Extracted URLs are never auto-opened, and they are defanged (`hxxp`, `[.]`) by default.

Email content is treated as data, never as instructions. Nothing parsed out of a message
can change how the application behaves.

Network lookups (redirect inspection) are opt-in and disabled by default. That subsystem
is treated as SSRF-sensitive: private, loopback, link-local, and reserved destinations
are rejected, redirects are revalidated, response size and time are bounded, and
cookies/credentials are never forwarded. It does not ship enabled in v1.

The full analysis is in [docs/threat-model.md](docs/threat-model.md) and
[docs/security-model.md](docs/security-model.md).

## Dependency hygiene

The runtime dependencies (fastapi, uvicorn, reportlab, pydantic, python-multipart) are
audited with `pip-audit` and come back clean. The React frontend is a build-time concern
only: what actually ships is the static `dist/` served by FastAPI, so `vite` and
`esbuild` never run in production. `esbuild` is pinned to a patched release via an
`overrides` entry. The remaining `npm audit` advisories apply only to the vite dev server
(`npm run dev`), which binds to localhost, so they do not reach the deployed application.
Moving past the vite 5.x line is a breaking change, and I am leaving it until the
toolchain is revalidated.

## Supported versions

v1.x receives security fixes. This is a portfolio and defensive-research project, so run
it local-only and do not expose it to untrusted networks.
