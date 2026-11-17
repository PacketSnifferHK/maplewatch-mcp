from conftest import ARCHIVE

from maplewatch.advisories import from_archive_item
from maplewatch.inventory import Software
from maplewatch.matcher import check

ADVISORIES = [a for a in (from_archive_item(i, "en") for i in ARCHIVE) if a]


def sw(name, version, *aliases):
    return Software(name=name, version=version, source="stack file", aliases=list(aliases))


def by_serial(findings):
    return {(f.advisory.serial, f.software.name): f for f in findings}


def test_confirmed_hit_and_version_rule_out():
    findings, ruled_out = check([sw("GitLab", "19.5.5"), sw("n8n", "1.122.0")], ADVISORIES)
    hits = by_serial(findings)
    assert hits[("AV26-1168", "GitLab")].status == "affected"
    assert hits[("AV26-1168", "GitLab")].confidence == "exact"
    assert ("AV26-004", "n8n") not in hits and ruled_out >= 1  # 1.122.0 is already fixed


def test_vendor_match_finds_product_named_differently():
    findings, _ = check([sw("Roundcube", "1.6.14")], ADVISORIES)
    f = by_serial(findings)[("AV26-300", "Roundcube")]
    assert f.status == "affected" and f.confidence == "likely"  # advisory says 'Webmail'


def test_unknown_version_is_check_not_affected():
    findings, _ = check([sw("GitLab", "latest")], ADVISORIES)
    f = by_serial(findings)[("AV26-1168", "GitLab")]
    assert f.status == "check" and "pin a real version" in f.reason


def test_partial_name_match_is_only_check():
    findings, _ = check([sw("Server", "0.1")], ADVISORIES)  # 'Server' appears in 'Grafana MCP Server'
    f = by_serial(findings)[("AV26-796", "Server")]
    assert f.status == "check" and f.confidence == "possible"


def test_mislabelled_alert_does_not_match():
    findings, _ = check([sw("GitLab", "19.5.5")], ADVISORIES)
    assert ("AL26-013", "GitLab") not in by_serial(findings)


def test_all_versions_and_ordering():
    findings, _ = check([sw("Oldapp", "9.9"), sw("GitLab", "19.5.5"), sw("GitLab", "latest")], ADVISORIES)
    assert [f.status for f in findings] == sorted([f.status for f in findings], key=lambda s: s != "affected")
    assert by_serial(findings)[("AV25-001", "Oldapp")].status == "affected"
