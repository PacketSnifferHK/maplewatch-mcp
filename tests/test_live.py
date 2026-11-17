"""Talks to the real cyber.gc.ca. Skipped by default; run with MAPLEWATCH_LIVE=1 pytest -m live."""

import os

import pytest

from maplewatch.sources import CyberCentre

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("MAPLEWATCH_LIVE") != "1", reason="set MAPLEWATCH_LIVE=1 to hit cyber.gc.ca"),
]


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_live_archive_and_feed(tmp_path, lang):
    src = CyberCentre(cache_dir=tmp_path)
    items = src.advisories(lang)
    assert len(items) > 5000, "the archive should hold every advisory since 2016"
    recent = [a for a in items if a.kind == "advisory"][:50]
    with_products = sum(1 for a in recent if a.products)
    assert with_products >= 35, f"parser coverage dropped: {with_products}/50 recent advisories have products"
    assert not src.warnings, src.warnings
