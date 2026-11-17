import httpx
import pytest

from maplewatch.sources import ARCHIVE_TTL, FEED_TTL, CyberCentre, SourceError, make_client


def test_archive_and_feed_are_merged_newest_first(make_source):
    items = make_source().advisories("en")
    serials = [a.serial for a in items]
    assert serials[0] in ("AV26-1169", "AV26-1168")
    assert "AV26-1169" in serials  # only in the feed
    assert "AV26-9999" not in serials  # feed entry pointing at another host is dropped
    gitlab = next(a for a in items if a.serial == "AV26-1168")
    assert [r.raw for r in gitlab.products[0].rules] == ["Prior to 19.5.6"]  # the feed version wins


def test_polite_caching(make_source, fake, clock):
    src = make_source()
    src.advisories("en")
    src.advisories("en")
    assert fake.calls == {"archive": 1, "feed": 1}
    clock.t += FEED_TTL + 1
    src.advisories("en")
    assert fake.calls == {"archive": 1, "feed": 2}
    clock.t += ARCHIVE_TTL + 1
    src.advisories("en")
    assert fake.calls["archive"] == 2


def test_disk_cache_survives_restart_and_offline(make_source, fake, clock):
    make_source().advisories("en")
    fake.fail = True
    clock.t += ARCHIVE_TTL + 1  # stale, and the network is down
    second = make_source()  # a new process
    items = second.advisories("en")
    assert any(a.serial == "AV26-1168" for a in items)
    assert any("cached" in w for w in second.warnings)


def test_no_cache_and_no_network_is_a_clear_error(make_source, fake):
    fake.fail = True
    with pytest.raises(SourceError, match="no cache yet"):
        make_source().advisories("en")


def test_redirects_off_site_are_blocked(make_source, fake):
    fake.redirect_to = "https://attacker.example/steal"
    with pytest.raises(SourceError):
        make_source().advisories("en")


def test_only_https_cyber_centre_is_allowed():
    client = make_client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    for url in ["http://www.cyber.gc.ca/x", "https://evil.example/x", "https://cyber.gc.ca.evil.example/x"]:
        with pytest.raises(SourceError):
            client.get(url)


def test_response_size_cap(tmp_path, monkeypatch):
    import maplewatch.sources as s

    monkeypatch.setattr(s, "MAX_BYTES", 1000)
    client = make_client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 5000)))
    with pytest.raises(SourceError):
        CyberCentre(cache_dir=tmp_path, client=client).advisories("en")


def test_bad_language_rejected(make_source):
    with pytest.raises(ValueError):
        make_source().advisories("de")
