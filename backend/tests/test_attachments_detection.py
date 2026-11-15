from phishlab.attachments import inspect_all
from phishlab.detection import AnalysisContext, run
from phishlab.indicators import extract
from phishlab.parser import parse
from tests.conftest import sample


def _analyze(name: str):
    p = parse(sample(name))
    att = inspect_all(p.attachments)
    return p, run(AnalysisContext(parsed=p, indicators=extract(p), attachments=att))


def test_double_extension_detected():
    p = parse(sample("07_double_extension.eml"))
    reports = inspect_all(p.attachments)
    r = reports[0]
    assert any(f.startswith("double-extension:") for f in r.flags)
    assert len(r.sha256) == 64


def test_mime_mismatch_detected():
    p = parse(sample("08_mime_mismatch.eml"))
    r = inspect_all(p.attachments)[0]
    assert any(f.startswith("ext-magic-mismatch:") for f in r.flags)


def test_flagship_produces_expected_rules():
    _, assessment = _analyze("00_flagship_bank_phish.eml")
    ids = {f.rule_id for f in assessment.findings}
    # Reply-To mismatch, auth fails, punycode URL, credential/login, double-extension
    assert "PL-SENDER-002" in ids
    assert "PL-AUTH-001" in ids and "PL-AUTH-003" in ids
    assert "PL-URL-002" in ids
    assert "PL-ATT-001" in ids
    assert assessment.highest_severity in ("high", "critical")


def test_severity_and_confidence_are_independent_fields():
    _, assessment = _analyze("00_flagship_bank_phish.eml")
    f = assessment.findings[0]
    assert f.severity in ("informational", "low", "medium", "high", "critical")
    assert f.confidence in ("low", "medium", "high")
    assert f.evidence and f.location and f.recommendation


def test_legitimate_email_low_noise():
    _, assessment = _analyze("01_legitimate.eml")
    high = assessment.counts.get("high", 0) + assessment.counts.get("critical", 0)
    assert high == 0  # no false high-severity on a clean, aligned, authed email


def test_every_finding_has_evidence_and_rule_id():
    _, assessment = _analyze("00_flagship_bank_phish.eml")
    for f in assessment.findings:
        assert f.rule_id and f.evidence and f.explanation
