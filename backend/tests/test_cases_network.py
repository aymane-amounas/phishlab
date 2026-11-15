import pytest

from phishlab.cases import CaseStore
from phishlab.engine import analyze_artifact
from phishlab.ingestion import ingest_bytes
from phishlab.network import (
    NetworkDisabled,
    UnsafeDestination,
    check_destination,
    check_scheme,
    inspect_redirects,
)
from tests.conftest import sample


@pytest.fixture
def store():
    s = CaseStore(db_path=":memory:")
    yield s
    s.close()


def _case(store, name="00_flagship_bank_phish.eml"):
    art = ingest_bytes(sample(name), source_kind="eml", declared_filename=name)
    return store.create(analyze_artifact(art))


def test_case_crud_and_disposition(store):
    cid = _case(store)
    case = store.get(cid)
    assert case["analysis"]["assessment"]["highest_severity"] in ("high", "critical")
    assert store.update_disposition(cid, "malicious", "Spoofed bank, failed auth, exec attachment")
    assert store.get(cid)["disposition"] == "malicious"
    assert store.update_notes(cid, "Escalated to IR.")
    assert store.get(cid)["notes"] == "Escalated to IR."


def test_invalid_disposition_rejected(store):
    cid = _case(store)
    with pytest.raises(ValueError):
        store.update_disposition(cid, "totally-bad", None)


def test_search_and_stats(store):
    _case(store)
    _case(store, "01_legitimate.eml")
    assert store.stats()["total"] == 2
    hits = store.list(q="SecureBank")
    assert len(hits) == 1


def test_delete(store):
    cid = _case(store)
    assert store.delete(cid) is True
    assert store.get(cid) is None


# ---- SSRF guards ----


def test_scheme_allowlist():
    check_scheme("https")
    with pytest.raises(UnsafeDestination):
        check_scheme("file")
    with pytest.raises(UnsafeDestination):
        check_scheme("gopher")


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1"])
def test_private_and_loopback_blocked(ip):
    chk = check_destination(ip)
    assert chk.safe is False


def test_public_ip_allowed():
    # A genuinely global, non-reserved address (TEST-NET ranges are correctly blocked).
    assert check_destination("93.184.216.34").safe is True


def test_dns_resolving_to_private_blocked():
    def fake_resolver(host, port):
        return [(2, 1, 6, "", ("10.1.2.3", 0))]

    chk = check_destination("rebind.example.test", resolver=fake_resolver)
    assert chk.safe is False and "blocked IP" in (chk.reason or "")


def test_network_disabled_by_default():
    with pytest.raises(NetworkDisabled):
        inspect_redirects("https://example.com")
