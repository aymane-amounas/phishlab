# PhishLab

**Understand suspicious emails. Investigate the evidence. Make informed security decisions.**

PhishLab is a safe, offline-first phishing investigation workbench for SOC analysts,
help desks, and security-conscious users. Import a suspicious `.eml`, and PhishLab parses
the headers and MIME structure, extracts indicators, defangs URLs, inspects attachment
metadata **without ever executing anything**, and produces evidence-linked findings you
can turn into a JSON or PDF report.

It is built around three non-negotiables:

1. **Evidence before scores.** Every finding has a rule id, severity, independent
   confidence, concrete evidence, and a source location. No black-box phishing percentage.
2. **Offline-first is real.** Static analysis makes zero outbound network calls. Fully
   useful without VirusTotal, urlscan, or any third party.
3. **Network isolation is not optional.** Optional URL/redirect inspection is treated as
   an SSRF-sensitive subsystem and ships **disabled by default**.

> PhishLab never executes attachments, never renders untrusted HTML, and never
> auto-opens extracted links. Treat it as an evidence surface for a human analyst - not
> an oracle that returns a verdict.

## Features

- `.eml` upload, raw header paste, and plain-text body input
- Full header + MIME tree parsing (multipart, nested, encoded/internationalized headers,
  malformed input handled defensively)
- Sender identity analysis: display-name / Reply-To / Return-Path / From alignment
- Authentication results parsing - clearly labeled **sender-reported**, not verified
- Indicator extraction: URLs, domains, IPv4/IPv6, emails, attachment metadata, hashes
- Punycode/IDN and suspicious-Unicode detection, lookalike-domain analysis
- Safe URL defanging (`hxxps://example[.]com`) + component breakdown
- Static attachment inspection: name, declared MIME, magic-byte type, size, SHA-256,
  double-extension and MIME-mismatch detection - **no execution, ever**
- Transparent rule-based detection engine (severity vs confidence)
- SQLite case management with notes, analyst disposition, search
- JSON (versioned schema) and PDF reports, defanged, with redaction option
- Opt-in, SSRF-hardened redirect inspection (disabled by default)

## Quick start

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn phishlab.main:app --host 127.0.0.1 --port 8000

# Frontend (separate terminal)
cd frontend
npm install && npm run dev
```

Or with Docker (binds to localhost only):

```bash
docker compose up --build
```

See [docs/](docs/) for architecture, email parsing, detection rules, privacy, the
security model, the SSRF-safe network design, the report schema, and deployment.

## Safety & privacy

Offline by default. No telemetry. Attachments are never executed. Untrusted HTML is never
rendered. All sample emails in this repo are **synthetic** - no real addresses,
credentials, or private data. See [SECURITY.md](SECURITY.md),
[docs/threat-model.md](docs/threat-model.md), and [docs/privacy.md](docs/privacy.md).

## Status

Early but functional. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for an
honest, per-milestone breakdown of what is built, tested, and deferred.

## License

MIT - see [LICENSE](LICENSE).

---
<sub>Built by [Aymane](https://github.com/aymane-amounas)</sub>
