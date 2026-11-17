"""Fetching Cyber Centre advisories politely: one host, HTTPS only, size limits, and a disk cache.

Two public endpoints, both used by cyber.gc.ca's own pages:
  * the archive (every advisory since 2016, with full text): fetched at most once a day
  * the Atom feed (latest 50): fetched at most every 15 minutes, so new advisories show up quickly
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

import httpx
from defusedxml import ElementTree as SafeET
from platformdirs import user_cache_dir

from . import __version__
from .advisories import SERIAL_RE, Advisory, Product, from_archive_item, parse_body, title_vendor
from .text import clean
from .versions import parse_rules

SITE = "https://www.cyber.gc.ca"
ALLOWED_HOSTS = frozenset({"www.cyber.gc.ca", "cyber.gc.ca"})
LANGS = ("en", "fr")
ARCHIVE_TTL = 24 * 3600
FEED_TTL = 15 * 60
MAX_BYTES = 60 * 1024 * 1024  # the archive is ~20 MB uncompressed
USER_AGENT = f"maplewatch-mcp/{__version__} (+https://github.com/PacketSnifferHK/maplewatch-mcp)"
_ATOM = "{http://www.w3.org/2005/Atom}"


class SourceError(RuntimeError):
    pass


def _only_cyber_centre(request: httpx.Request) -> None:
    """Runs before every request, redirects included: nothing but https://www.cyber.gc.ca."""
    if request.url.scheme != "https" or request.url.host not in ALLOWED_HOSTS:
        raise SourceError(f"blocked request to {request.url.scheme}://{request.url.host}")


def make_client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"},
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
        max_redirects=3,
        event_hooks={"request": [_only_cyber_centre]},
        transport=transport,
    )


def _to_dict(a: Advisory) -> dict:
    d = asdict(a)
    d["products"] = [{"name": p.name, "rules": list(dict.fromkeys(r.raw for r in p.rules))} for p in a.products]
    return d


def _from_dict(d: dict) -> Advisory:
    products = [Product(p["name"], [r for raw in p["rules"] for r in parse_rules(raw)]) for p in d.pop("products", [])]
    return Advisory(**d, products=products)


def from_atom_entry(entry, lang: str) -> Advisory | None:
    title = clean(entry.findtext(f"{_ATOM}title"), 300)
    m = SERIAL_RE.search(title.replace("–", "-"))
    link = entry.find(f"{_ATOM}link")
    href = link.get("href") if link is not None else ""
    if not m or urlparse(href or "").hostname not in ALLOWED_HOSTS:
        return None
    products, cves, refs, intro = parse_body(entry.findtext(f"{_ATOM}content") or "")
    return Advisory(
        serial=m.group(1),
        title=title,
        url=href.replace("https://cyber.gc.ca", SITE, 1),
        lang=lang,
        published=(entry.findtext(f"{_ATOM}updated") or "")[:10],
        vendor=title_vendor(title),
        products=products,
        cves=cves,
        references=refs,
        intro=intro,
    )


class CyberCentre:
    """All advisories in one language, newest first, with caching and an offline fallback."""

    def __init__(
        self,
        cache_dir: str | os.PathLike[str] | None = None,
        client: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cache_dir = Path(cache_dir or os.environ.get("MAPLEWATCH_CACHE_DIR") or user_cache_dir("maplewatch"))
        self.client = client or make_client()
        self.clock = clock
        self._lock = threading.Lock()
        self._memory: dict[str, tuple[float, float, list[Advisory]]] = {}  # lang -> (archive_at, feed_at, list)
        self.warnings: list[str] = []

    # ---------- network ----------
    def _get(self, url: str) -> bytes:
        with self.client.stream("GET", url) as r:
            r.raise_for_status()
            chunks, size = [], 0
            for chunk in r.iter_bytes():
                size += len(chunk)
                if size > MAX_BYTES:
                    raise SourceError(f"response larger than {MAX_BYTES} bytes")
                chunks.append(chunk)
            return b"".join(chunks)

    def _fetch_archive(self, lang: str) -> list[Advisory]:
        data = json.loads(self._get(f"{SITE}/api/cccs/threats/v1/get?lang={lang}&content_type=cccs_threat"))
        items = data.get("response") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise SourceError("archive response has an unexpected shape")
        advisories = [a for a in (from_archive_item(i, lang) for i in items if isinstance(i, dict)) if a]
        if not advisories:
            raise SourceError("archive response contained no advisories")
        return advisories

    def _fetch_feed(self, lang: str) -> list[Advisory]:
        root = SafeET.fromstring(self._get(f"{SITE}/api/cccs/atom/v1/get?feed=alerts_advisories&lang={lang}"))
        return [a for a in (from_atom_entry(e, lang) for e in root.findall(f"{_ATOM}entry")) if a]

    # ---------- disk cache ----------
    def _path(self, lang: str) -> Path:
        return self.cache_dir / f"advisories-{lang}.json"

    def _load_disk(self, lang: str) -> tuple[float, list[Advisory]] | None:
        try:
            raw = json.loads(self._path(lang).read_text(encoding="utf-8"))
            return float(raw["fetched_at"]), [_from_dict(d) for d in raw["advisories"]]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _save_disk(self, lang: str, fetched_at: float, advisories: list[Advisory]) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = self._path(lang).with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"fetched_at": fetched_at, "advisories": [_to_dict(a) for a in advisories]}), encoding="utf-8"
        )
        tmp.replace(self._path(lang))

    # ---------- public ----------
    def advisories(self, lang: str = "en") -> list[Advisory]:
        if lang not in LANGS:
            raise ValueError("lang must be 'en' or 'fr'")
        with self._lock:
            self.warnings = []
            now = self.clock()
            archive_at, feed_at, items = self._memory.get(lang, (0.0, 0.0, []))
            if not items and (disk := self._load_disk(lang)):
                archive_at, items = disk
            if now - archive_at > ARCHIVE_TTL:
                try:
                    items, archive_at, feed_at = self._fetch_archive(lang), now, 0.0
                    self._save_disk(lang, now, items)
                except (httpx.HTTPError, SourceError, ValueError) as exc:
                    if not items:
                        raise SourceError(f"can't reach the Cyber Centre and there is no cache yet: {exc}") from exc
                    self.warnings.append(f"using cached advisories from {time.ctime(archive_at)}: {exc}")
            if now - feed_at > FEED_TTL:
                try:
                    by_serial = {a.serial: a for a in items}
                    by_serial.update({a.serial: a for a in self._fetch_feed(lang)})  # the feed is fresher
                    items = list(by_serial.values())
                    feed_at = now
                except (httpx.HTTPError, SourceError, SafeET.ParseError, ValueError) as exc:
                    self.warnings.append(f"latest-feed check failed, results may miss today's advisories: {exc}")
            items.sort(key=lambda a: (a.published, a.serial), reverse=True)
            self._memory[lang] = (archive_at, feed_at, items)
            return items
