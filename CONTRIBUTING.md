# Contributing to PhishLab

PhishLab is a defensive security tool, so any contribution has to preserve its safety
guarantees. These are the lines I will not move on:

- No code that executes, detonates, or opens attachments, or that visits extracted URLs
  in a real browser.
- No outbound network calls in the static-analysis path.
- No real `.eml` files, real email addresses, credentials, or secrets in the repo. The
  sample corpus stays 100% synthetic.
- Defang URLs in any user-facing or report-facing output by default.
- Parameterized SQL only.

## Dev setup

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Pull requests

A security feature is not done without a test that demonstrates it, so add tests for any
new parser, indicator, or detection rule. Update `docs/` and `IMPLEMENTATION_STATUS.md`
to match, and keep the modules isolated the way `docs/architecture.md` describes.
