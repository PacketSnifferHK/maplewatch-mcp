from conftest import ARCHIVE

from maplewatch.advisories import from_archive_item, parse_body, title_vendor


def adv(serial):
    item = next(i for i in ARCHIVE if i["serial_number"] == serial)
    return from_archive_item(item, "en")


def test_nested_layout():
    a = adv("AV26-1168")
    assert a.serial == "AV26-1168" and a.kind == "advisory" and a.vendor == "gitlab"
    assert [p.name for p in a.products] == ["GitLab"]
    assert [r.raw for r in a.products[0].rules] == ["Prior to 19.3.9", "Prior to 19.4.8", "Prior to 19.5.6"]
    assert a.cves == ["CVE-2026-19516"]
    assert a.url == "https://www.cyber.gc.ca/en/alerts-advisories/gitlab-security-advisory-(av26-1168)"
    assert a.intro.startswith("As of November 17, 2026, GitLab is affected")


def test_flat_layout_and_repeated_product_lines_merge():
    a = adv("AV26-300")
    assert a.serial == "AV26-300"  # published with an en dash
    assert [(p.name, [r.raw for r in p.rules]) for p in a.products] == [
        ("Webmail", ["versions prior to 1.6.15", "versions prior to 1.5.15"])
    ]
    assert a.vendor == "roundcube"


def test_alert_instructions_are_not_products():
    a = adv("AL26-013")
    assert a.kind == "alert" and a.products == []
    assert a.vendor == "gitlab"  # only the (wrong) subject tag is left; matcher won't use vendor-only on alerts


def test_title_vendor_beats_wrong_subject():
    assert title_vendor("GitLab security advisory (AV26-1168)") == "gitlab"
    assert title_vendor("[Control systems] CODESYS security advisory (AV26-1169)") == "codesys"
    assert title_vendor("Avis de sécurité de GitLab (AV26-1168)") == "gitlab"
    assert title_vendor("Bulletin de sécurité GitLab (AV26-1168)") == "gitlab"  # real French title


def test_only_web_links_survive():
    _, _, refs, _ = parse_body(ARCHIVE[0]["body"][0])
    urls = [r["url"] for r in refs]
    assert "https://example.com/fix" in urls
    assert not any(u.startswith("javascript:") for u in urls)
