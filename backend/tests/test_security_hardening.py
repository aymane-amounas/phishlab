"""Parser robustness and SSRF guards against the adversarial corpus.

Every artifact here is hostile by construction. The invariant under test is simple:
analysis must always return a result and never raise, and the SSRF guards must hold
regardless of whether the network feature is enabled.
"""

import time

import pytest

from phishlab.defang import breakdown
from phishlab.engine import analyze_artifact
from phishlab.indicators import extract
from phishlab.ingestion import ingest_bytes
from phishlab.network import UnsafeDestination, check_destination
from phishlab.parser import parse
from tests.conftest import sample

ADVERSARIAL = [
    "00_flagship_bank_phish.eml",
    "10_malformed_headers.eml",
    "12_malformed_port.eml",
    "13_deeply_nested.eml",
    "14_idn_unicode_mix.eml",
    "15_oversized_header.eml",
]


@pytest.mark.parametrize("name", ADVERSARIAL)
def test_analysis_never_raises_on_hostile_input(name):
    analysis = analyze_artifact(ingest_bytes(sample(name)))
    assert isinstance(analysis["findings"], list)
    assert "assessment" in analysis


def test_malformed_port_does_not_crash_and_is_not_flagged_as_port():
    # Regression: urlsplit(...).port raises ValueError on out-of-range/non-numeric ports.
    analysis = analyze_artifact(ingest_bytes(sample("12_malformed_port.eml")))
    assert "Indicator extraction error" not in " ".join(analysis["warnings"])
    for u in analysis["indicators"]["urls"]:
        assert not any(f.startswith("unusual-port") for f in u["flags"])


def test_breakdown_bad_port_returns_none():
    assert breakdown("http://a.example.test:99999999/x").port is None
    assert breakdown("http://a.example.test:notaport/x").port is None
    assert breakdown("http://a.example.test:8080/x").port == 8080


def test_deeply_nested_mime_is_capped():
    parsed = parse(sample("13_deeply_nested.eml"))
    assert any("exceeded cap" in w for w in parsed.warnings)


def test_oversized_header_scan_is_bounded_in_time():
    start = time.monotonic()
    analyze_artifact(ingest_bytes(sample("15_oversized_header.eml")))
    # Generous bound: this detects a hang/catastrophic backtracking, not a perf regression.
    assert time.monotonic() - start < 20.0


def test_idn_and_zero_width_are_flagged():
    iset = extract(parse(sample("14_idn_unicode_mix.eml")))
    flags = {f for u in iset.urls for f in u.flags}
    assert any(f == "punycode-idn" for f in flags)
    assert any(f == "zero-width-char" or f == "non-ascii-domain" for f in flags)


@pytest.mark.parametrize(
    "host",
    ["169.254.169.254", "127.0.0.1", "0.0.0.0", "10.0.0.1", "192.168.0.1", "::1", "[::1]"],
)
def test_ssrf_blocks_private_and_metadata(host):
    assert check_destination(host).safe is False


def test_ssrf_blocks_ipv4_mapped_ipv6_loopback():
    assert check_destination("::ffff:127.0.0.1").safe is False


def test_ssrf_dns_rebinding_to_private_blocked():
    def resolver(h, p):
        return [(2, 1, 6, "", ("192.168.5.5", 0))]

    chk = check_destination("rebind.example.test", resolver=resolver)
    assert chk.safe is False


def test_ssrf_empty_host_rejected():
    with pytest.raises(UnsafeDestination):
        check_destination("")
