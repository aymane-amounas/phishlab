# Contributing to PhishLab

PhishLab is a defensive security tool. Contributions must preserve its safety guarantees.

## Hard rules

- **Never** add code that executes, detonates, or opens attachments, or that visits
  extracted URLs in a real browser.
- **Never** make outbound network calls in the static-analysis path.
- **Never** commit real `.eml` files, real email addresses, credentials, or secrets.
  Sample corpus must be 100% synthetic.
- Defang URLs in any user- or report-facing output by default.
- Use parameterized SQL only.

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

- Add tests for any new parser, indicator, or detection rule. A security feature is not
  "done" without a test demonstrating it.
- Update `docs/` and `IMPLEMENTATION_STATUS.md`.
- Keep modules isolated (see `docs/architecture.md`).
