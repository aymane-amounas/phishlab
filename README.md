<p align="center">
  <img src="assets/logo.png" width="520" alt="PhishLab - Understand suspicious emails. Investigate the evidence. Make informed security decisions." />
</p>

PhishLab is an offline-first workbench for investigating suspicious emails. You give it a
`.eml` (or pasted headers, or a plain-text body) and it parses the headers and MIME
structure, pulls out indicators, defangs the URLs, looks at attachment metadata without
running anything, and hands you findings that each point back at the evidence they came
from. You can then save the case and export a JSON or PDF report.

I built it around three ideas I did not want to compromise on.

The first is evidence before scores. Every finding carries a rule id, a severity, a
confidence that is tracked separately from severity, the concrete thing that matched, and
where in the message it matched. There is no single black-box "this is 87% phishing"
number, because I do not trust those and neither should an analyst.

The second is that offline-first has to be real, not a marketing line. The static
analysis makes zero outbound network calls. It is fully useful with no VirusTotal, no
urlscan, no third-party anything.

The third is that network isolation is not a toggle you flip casually. The optional
URL/redirect inspection is treated as an SSRF-sensitive subsystem and ships disabled by
default.

So treat PhishLab as an evidence surface for a human analyst, not an oracle that returns
a verdict. It never executes attachments, never renders untrusted HTML, and never
auto-opens extracted links.

## What it does

- `.eml` upload, raw header paste, and plain-text body input
- Header and MIME tree parsing: multipart, nested, encoded and internationalized headers,
  and malformed input handled without crashing
- Sender identity checks across display-name, Reply-To, Return-Path, and From
- Authentication results parsing, labeled as sender-reported rather than verified
- Indicator extraction: URLs, domains, IPv4/IPv6, emails, attachment metadata, hashes
- Punycode/IDN and suspicious-Unicode detection, plus lookalike-domain analysis
- URL defanging (`hxxps://example[.]com`) and a component breakdown
- Static attachment inspection: name, declared MIME, magic-byte type, size, SHA-256,
  double-extension and MIME-mismatch flags, with no execution at any point
- A rule-based detection engine where severity and confidence are reported separately
- SQLite case management with notes, analyst disposition, and search
- JSON (versioned schema) and PDF reports, defanged, with an optional redaction pass
- Opt-in redirect inspection with SSRF guards, disabled by default

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

Or with Docker, which binds to localhost only:

```bash
docker compose up --build
```

The [docs/](docs/) folder covers architecture, email parsing, detection rules, privacy,
the security model, the SSRF-safe network design, the report schema, and deployment.

## Investigation workflow

Here is a full pass on one suspicious email, done through the API. The UI drives the same
endpoints, so this is just the plumbing underneath it.

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

The flagship sample is built to exercise every surface at once: a spoofed bank sender, a
Reply-To mismatch, failed SPF/DKIM/DMARC (sender-reported), a punycode
credential-harvesting URL, and a double-extension executable attachment. None of it is
ever opened, rendered, or fetched.

## Safety and privacy

Offline by default, no telemetry. Attachments are never executed and untrusted HTML is
never rendered. Every sample email in this repo is synthetic, with no real addresses,
credentials, or private data. For the details see [SECURITY.md](SECURITY.md),
[docs/threat-model.md](docs/threat-model.md), and [docs/privacy.md](docs/privacy.md).

## Status

Early but functional. [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) has a
per-milestone breakdown of what is built, tested, and deferred.

## License

Aymane Amounas Noncommercial Attribution License 1.0, see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Noncommercial use only; commercial use requires a separate written
agreement with the copyright holder.

---
<sub>Built by [Aymane](https://github.com/aymane-amounas)</sub>
