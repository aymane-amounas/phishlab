<p align="center">
  <img src="assets/logo.png" width="520" alt="PhishLab - Understand suspicious emails. Investigate the evidence. Make informed security decisions." />
</p>

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

## Investigation workflow

A full pass on one suspicious email, API-first (the UI drives the same endpoints):

```bash
# 1. Import and analyze an .eml, persisting it as a case
curl -s -F file=@backend/samples/corpus/00_flagship_bank_phish.eml \
  http://127.0.0.1:8000/api/cases > case.json
CID=$(python -c "import json;print(json.load(open('case.json'))['id'])")

# 2. Read the evidence: parsed headers, auth results, indicators, findings
python -c "import json;a=json.load(open('case.json'))['analysis'];\
print(a['summary_headers']['from']);\
print([f['rule_id'] for f in a['findings']])"

# 3. Indicators come back defanged (hxxp, [.]) and never auto-resolved
python -c "import json;a=json.load(open('case.json'))['analysis'];\
print([u['defanged'] for u in a['indicators']['urls']])"

# 4. Attachments are inspected statically only: magic bytes, sha256, risk flags
python -c "import json;a=json.load(open('case.json'))['analysis'];\
print([(x['filename'],x['detected_type'],x['flags']) for x in a['attachments']])"

# 5. Record a disposition after reviewing the evidence yourself
curl -s -X PATCH http://127.0.0.1:8000/api/cases/$CID/disposition \
  -H 'content-type: application/json' \
  -d '{"disposition":"malicious","rationale":"spoofed bank, failed auth, exec attachment"}'

# 6. Export a report (JSON or PDF), redacted by default
curl -s http://127.0.0.1:8000/api/cases/$CID/report.json > report.json
curl -s "http://127.0.0.1:8000/api/cases/$CID/report.pdf?redact=true" -o report.pdf
```

The flagship sample exercises every surface at once: spoofed bank sender, Reply-To
mismatch, failed SPF/DKIM/DMARC (sender-reported), a punycode credential-harvesting URL,
and a double-extension executable attachment. Nothing in it is ever opened, rendered, or
fetched.

## Safety & privacy

Offline by default. No telemetry. Attachments are never executed. Untrusted HTML is never
rendered. All sample emails in this repo are **synthetic** - no real addresses,
credentials, or private data. See [SECURITY.md](SECURITY.md),
[docs/threat-model.md](docs/threat-model.md), and [docs/privacy.md](docs/privacy.md).

## Status

Early but functional. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for an
honest, per-milestone breakdown of what is built, tested, and deferred.

## License

Aymane Amounas Noncommercial Attribution License 1.0 - see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Noncommercial use only; commercial use requires a separate written
agreement with the copyright holder.

---
<sub>Built by [Aymane](https://github.com/aymane-amounas)</sub>
