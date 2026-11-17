"""Shared fixtures. Advisory bodies follow the real cyber.gc.ca markup (two layouts) but are shortened.
Source of the originals: Canadian Centre for Cyber Security, reproduced for testing with attribution."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from maplewatch.sources import CyberCentre, make_client

NESTED = """<div class="field--name-body"><p><strong>Serial number: </strong>{serial}<br />
<strong>Date: </strong>November 17, 2026</p>
<p>As of November 17, 2026, {vendor} is affected by vulnerabilities in the following product:</p>
<ul>{products}</ul>
<p class="mrgn-bttm-md">The Cyber Centre encourages users and administrators to review the provided web links.</p>
<ul class="list-unstyled"><li><a href="https://example.com/fix">{vendor} patch release</a></li>
<li><a href="https://www.cve.org/CVERecord?id=CVE-2026-19516">CVE-2026-19516 CVE Record</a></li>
<li><a href="javascript:alert(1)">bad link</a></li></ul></div>"""

FLAT = """<div class="field--name-body"><p><strong>Serial number: </strong>{serial}</p>
<p>On January 6, 2026, {vendor} published security updates for the following product:</p>
<ul>{products}</ul>
<ul class="list-unstyled"><li><a href="/en/guidance/something">Guidance</a></li></ul></div>"""


def nested_products(products: dict[str, list[str]]) -> str:
    return "".join(
        f"<li>{name}\n<ul>{''.join(f'<li>{r}</li>' for r in rules)}</ul></li>" for name, rules in products.items()
    )


def flat_products(lines: list[str]) -> str:
    return "".join(f"<li>{line}</li>" for line in lines)


def archive_item(serial: str, title: str, date: str, body: str, subject: str | None = None) -> dict:
    slug = title.lower().replace(" ", "-")
    return {
        "nid": "1",
        "title": title,
        "lang": "en",
        "date_created": f"{date}T12:00:00Z",
        "date_modified": date,
        "body": [f'<article class="cccs-threats">{body}</article>'],
        "url": f"/en/alerts-advisories/{slug}",
        "serial_number": serial,
        "subject": subject,
        "moderation_state": "published",
    }


ARCHIVE = [
    archive_item(
        "AV26-1168",
        "GitLab security advisory (AV26-1168)",
        "2026-11-17",
        NESTED.format(
            serial="AV26-1168",
            vendor="GitLab",
            products=nested_products({"GitLab": ["Prior to 19.3.9", "Prior to 19.4.8", "Prior to 19.5.6"]}),
        ),
        subject="gitlab",
    ),
    archive_item(
        "AV26-796",
        "Grafana security advisory (AV26-796)",
        "2026-08-11",
        NESTED.format(
            serial="AV26-796",
            vendor="Grafana",
            products=nested_products(
                {"Grafana MCP Server": ["Prior to or equal to 1.0.0"], "mcp-grafana": ["Prior to or equal to 1.0.0"]}
            ),
        ),
    ),
    archive_item(
        "AV26-004",
        "n8n security advisory (AV26-004)",
        "2026-01-07",
        FLAT.format(
            serial="AV26-004",
            vendor="n8n",
            products=flat_products(["n8n – versions 0.123.0 to versions prior to 1.121.3"]),
        ),
        subject="other",
    ),
    archive_item(
        "AV26-300",
        "Roundcube security advisory (AV26–300)",
        "2026-03-30",  # en dash in the serial, as published
        FLAT.format(
            serial="AV26–300",
            vendor="Roundcube",
            products=flat_products(["Webmail – versions prior to 1.6.15", "Webmail – versions prior to 1.5.15"]),
        ),
    ),
    archive_item(
        "AL26-013",
        "AL26-013 Security incident impacting GitHub internal repositories",
        "2026-05-21",
        NESTED.format(
            serial="AL26-013",
            vendor="GitHub",
            products=nested_products(
                {
                    "If the malicious version of Nx Console is present:": [
                        "Rotate all credentials exposed between May 11–20, 2026."
                    ]
                }
            ),
        ),
        subject="gitlab",  # the real archive mislabels this one; maplewatch must not trust it
    ),
    archive_item(
        "AV25-001",
        "Oldvendor security advisory (AV25-001)",
        "2025-01-02",
        NESTED.format(serial="AV25-001", vendor="Oldvendor", products=nested_products({"Oldapp": ["All versions"]})),
    ),
]

ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>https://cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&amp;lang=en</id>
  <title>Alerts and advisories</title>
  <updated>2026-11-17T19:17:56Z</updated>
  {entries}
</feed>"""


def atom_entry(serial: str, title: str, date: str, body: str, host: str = "cyber.gc.ca") -> str:
    from xml.sax.saxutils import escape

    url = f"https://{host}/en/alerts-advisories/{serial.lower()}"
    return (
        f'<entry><id>{url}</id><link rel="alternate" href="{url}"/><title>{escape(title)}</title>'
        f"<updated>{date}T19:17:56Z</updated><summary></summary><content>{escape(body)}</content></entry>"
    )


FEED_ENTRIES = [
    atom_entry(
        "AV26-1169",
        "[Control systems] CODESYS security advisory (AV26-1169)",
        "2026-11-17",
        NESTED.format(
            serial="AV26-1169",
            vendor="CODESYS",
            products=nested_products({"CODESYS Service Tool": ["Prior to 1.40.0.0"]}),
        ),
    ),
    atom_entry(
        "AV26-1168",
        "GitLab security advisory (AV26-1168)",
        "2026-11-17",
        NESTED.format(serial="AV26-1168", vendor="GitLab", products=nested_products({"GitLab": ["Prior to 19.5.6"]})),
    ),
    atom_entry("AV26-9999", "Evil security advisory (AV26-9999)", "2026-11-17", "<p>x</p>", host="evil.example"),
]


class FakeCyberCentre:
    """Counts requests per endpoint and serves the fixtures above."""

    def __init__(self, archive: list[dict] | None = None, feed: list[str] | None = None) -> None:
        self.archive = ARCHIVE if archive is None else archive
        self.feed = FEED_ENTRIES if feed is None else feed
        self.calls: dict[str, int] = {"archive": 0, "feed": 0}
        self.fail = False
        self.redirect_to: str | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            raise httpx.ConnectError("network down", request=request)
        if self.redirect_to:
            return httpx.Response(301, headers={"location": self.redirect_to})
        if request.url.path == "/api/cccs/threats/v1/get":
            self.calls["archive"] += 1
            return httpx.Response(200, json={"ERROR": False, "response": self.archive})
        if request.url.path == "/api/cccs/atom/v1/get":
            self.calls["feed"] += 1
            return httpx.Response(
                200, text=ATOM.format(entries="".join(self.feed)), headers={"content-type": "application/xml"}
            )
        return httpx.Response(404)


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def fake() -> FakeCyberCentre:
    return FakeCyberCentre()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def make_source(tmp_path, fake, clock) -> Callable[..., CyberCentre]:
    def _make(**kw) -> CyberCentre:
        client = make_client(transport=httpx.MockTransport(fake.handler))
        return CyberCentre(cache_dir=tmp_path / "cache", client=client, clock=clock, **kw)

    return _make


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def dumps(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False)
