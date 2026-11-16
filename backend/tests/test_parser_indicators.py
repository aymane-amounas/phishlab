from phishlab.defang import breakdown, defang_url, refang
from phishlab.indicators import extract
from phishlab.parser import parse
from tests.conftest import sample


def test_parse_flagship_headers():
    p = parse(sample("00_flagship_bank_phish.eml"))
    assert "secure-bank.example.net" in (p.from_ or "")
    assert "bank-security-team.invalid" in (p.reply_to or "")
    assert p.subject and "SUSPENDED" in p.subject.upper()
    assert p.message_id


def test_auth_results_are_sender_reported_not_verified():
    p = parse(sample("00_flagship_bank_phish.eml"))
    assert p.auth.spf == "fail"
    assert p.auth.dkim == "fail"
    assert p.auth.dmarc == "fail"
    assert p.auth.verified is False  # NEVER claim verification


def test_malformed_headers_do_not_crash():
    p = parse(sample("10_malformed_headers.eml"))
    assert isinstance(p.warnings, list)  # parsed defensively, no exception


def test_empty_email_does_not_crash():
    p = parse(sample("11_empty.eml"))
    assert p.warnings  # records a warning rather than raising


def test_nested_multipart_walks_parts_and_attachment():
    p = parse(sample("09_nested_multipart.eml"))
    assert any(part.content_type == "text/html" for part in p.parts)
    assert p.body_html is not None  # kept as SOURCE
    assert any(a.filename == "data.csv" for a in p.attachments)


def test_indicator_extraction_ip_and_port():
    p = parse(sample("05_ip_url.eml"))
    iset = extract(p)
    url = iset.urls[0]
    assert "ip-based-url" in url.flags
    assert any(f.startswith("unusual-port:8080") for f in url.flags)


def test_indicator_punycode_flagged_and_decoded():
    p = parse(sample("04_punycode.eml"))
    iset = extract(p)
    assert any("punycode-idn" in u.flags for u in iset.urls)


def test_defang_roundtrip():
    url = "https://evil.example.com/login"
    d = defang_url(url)
    assert d == "hxxps://evil[.]example[.]com/login"
    assert refang(d) == url


def test_breakdown_ip_literal():
    bd = breakdown("http://203.0.113.5:8080/x")
    assert bd.is_ip_literal is True
    assert bd.port == 8080


def test_breakdown_out_of_range_port_does_not_crash():
    # A crafted out-of-range port must not raise (analysis treats hostile input).
    bd = breakdown("http://1.2.3.4:999999/login")
    assert bd.port is None
    assert bd.host == "1.2.3.4"


def test_analysis_survives_out_of_range_port_url():
    from phishlab.engine import analyze_artifact
    from phishlab.ingestion import ingest_text

    artifact = ingest_text("Subject: x\n\nclick http://1.2.3.4:999999/login", source_kind="text")
    result = analyze_artifact(artifact)  # must not raise
    assert any(u["value"].startswith("http://1.2.3.4:999999") for u in result["indicators"]["urls"])


def test_field_scan_is_capped(monkeypatch):
    # A huge body must not hang extraction.
    from phishlab.parser import ParsedEmail

    p = ParsedEmail(body_text="https://a.example.com " * 100000)
    iset = extract(p)
    assert len(iset.urls) >= 1
