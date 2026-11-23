import time

import pytest

from maplewatch.versions import evaluate, parse_rule, parse_rules, version_key


def rules(*texts: str):
    return [r for t in texts for r in parse_rules(t)]


GITLAB = ("Prior to 19.3.9", "Prior to 19.4.8", "Prior to 19.5.6")
GRAFANA = ("versions prior to 12.4.2, 12.3.6, 12.2.8, 12.1.10 and 11.6.14",)
N8N = ("versions prior to 1.123.10 and versions prior to 2.5.0",)


@pytest.mark.parametrize(
    ("installed", "texts", "expected"),
    [
        # one release line per fixed version (GitLab style)
        ("19.5.5", GITLAB, "affected"),
        ("19.5.6", GITLAB, "not_affected"),
        ("19.4.1", GITLAB, "affected"),
        ("19.2.0", GITLAB, "affected"),
        ("19.6.0", GITLAB, "not_affected"),
        # a list of fixes in one sentence (Grafana style)
        ("12.3.7", GRAFANA, "not_affected"),
        ("12.3.5", GRAFANA, "affected"),
        ("11.6.13", GRAFANA, "affected"),
        ("12.5.0", GRAFANA, "not_affected"),
        # lines that differ by major version (n8n style)
        ("2.4.1", N8N, "affected"),
        ("2.5.0", N8N, "not_affected"),
        ("1.120.4", N8N, "affected"),
        ("1.124.0", N8N, "not_affected"),
        # single bounds and ranges
        ("1.0.0", ("Prior to or equal to 1.0.0",), "affected"),
        ("1.0.1", ("Prior to or equal to 1.0.0",), "not_affected"),
        ("1.121.2", ("versions 0.123.0 to versions prior to 1.121.3",), "affected"),
        ("1.121.3", ("versions 0.123.0 to versions prior to 1.121.3",), "not_affected"),
        ("0.122.0", ("versions 0.123.0 to versions prior to 1.121.3",), "not_affected"),
        ("15.2.2", ("15.x versions prior to 15.2.3",), "affected"),
        ("16.0.0", ("15.x versions prior to 15.2.3",), "not_affected"),
        ("3.15.1", ("versions 3.15.x prior to 3.15.2",), "affected"),
        ("9.0p1", ("versions 6.8p1 to 9.9p1",), "affected"),
        ("8.0.5", ("version 8.0",), "affected"),
        ("8.1", ("version 8.0",), "not_affected"),
        ("8.1.2", ("Versions 8.0, 8.1 and 8.2",), "affected"),
        ("1.40.0.0", ("Prior to 1.40.0.0",), "not_affected"),
        ("1.39", ("Prior to 1.40.0.0",), "affected"),
        # French
        ("19.5.5", ("Versions antérieures à la version 19.5.6",), "affected"),
        ("1.0.0", ("Versions antérieures jusqu'à la version 1.0.0",), "affected"),
        ("4.2", ("Version 4.2 et versions antérieures",), "affected"),
        ("2.1", ("De la version 2.0 à 2.4",), "affected"),
        ("3.0.8", ("Versions antérieures à la version 3.1.2, 3.0.9 et 2.9.14",), "affected"),
        ("3.0.9", ("Versions antérieures à la version 3.1.2, 3.0.9 et 2.9.14",), "not_affected"),
        # never guess
        ("2.0", ("All versions",), "affected"),
        ("2.0", ("Toutes les versions",), "affected"),
        ("1.0", ("Multiple versions",), "unknown"),
        ("latest", ("Prior to 2.0",), "unknown"),
        (None, ("Prior to 2.0",), "unknown"),
        ("22.7.2", ("version 22.7R2.5 and prior",), "unknown"),  # vendor scheme, too close to call
        ("21.9", ("version 22.7R2.5 and prior",), "affected"),
        ("23.1", ("version 22.7R2.5 and prior",), "not_affected"),
    ],
)
def test_verdicts(installed, texts, expected):
    verdict, reason = evaluate(installed, rules(*texts))
    assert verdict == expected, reason
    assert reason


def test_version_key():
    assert version_key("v1.40.0.0") == (1, 40, 0, 0)
    assert version_key("11.0.0-M1") == (11, 0, 0)
    assert version_key("latest") is None
    assert version_key("") is None


def test_unreadable_rules_are_kept_for_humans():
    r = parse_rule("ALL except ComboAM5PI 1.2.0.3")
    assert r.kind == "unknown" and r.raw == "ALL except ComboAM5PI 1.2.0.3"


@pytest.mark.parametrize(
    "evil",
    [
        "versions " + "1." * 20000 + "x",
        "versions " + ", ".join(["1.2.3"] * 5000) + " and",
        "1" + ".1" * 20000 + "a" * 50 + " !",
        "Prior to " + "9" * 50000,
    ],
)
def test_no_catastrophic_backtracking(evil, monkeypatch):
    """Regression test: an early regex was quadratic on long lists (ReDoS, ~3 s for 8,000 chars). Must stay linear."""
    import maplewatch.versions as v

    monkeypatch.setattr(v, "MAX_RULE_CHARS", 10**6)  # test the regexes, not the length cap
    start = time.perf_counter()
    v.parse_rules(evil)
    assert time.perf_counter() - start < 0.5
