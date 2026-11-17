"""Advisory model and parsing of the Cyber Centre's advisory HTML into products, version rules and CVEs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .text import clean, norm_name
from .versions import Rule, parse_rules

SITE = "https://www.cyber.gc.ca"
SERIAL_RE = re.compile(r"\b([A-Z]{2}\d{2}-\d{1,5})\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_KIND = {"AV": "advisory", "AL": "alert", "IN": "information", "TR": "technical report"}


@dataclass
class Product:
    name: str
    rules: list[Rule] = field(default_factory=list)


@dataclass
class Advisory:
    serial: str
    title: str
    url: str
    lang: str
    published: str  # ISO date, YYYY-MM-DD
    vendor: str = ""
    products: list[Product] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    references: list[dict[str, str]] = field(default_factory=list)
    intro: str = ""

    @property
    def kind(self) -> str:
        return _KIND.get(self.serial[:2], "other")

    def summary(self) -> dict[str, object]:
        return {
            "serial": self.serial,
            "kind": self.kind,
            "title": self.title,
            "published": self.published,
            "vendor": self.vendor,
            "products": [p.name for p in self.products][:20],
            "cves": self.cves[:20],
            "url": self.url,
        }

    def details(self) -> dict[str, object]:
        return {
            **self.summary(),
            "intro": self.intro,
            "affected": [{"product": p.name, "versions": [r.raw for r in p.rules]} for p in self.products],
            "references": self.references,
        }


def _safe_link(href: str | None) -> str | None:
    if not href:
        return None
    url = urljoin(SITE, href.strip())
    if urlparse(url).scheme not in ("http", "https") or len(url) > 500:
        return None
    return url


# "Webmail – versions prior to 1.6.15": product, dash, version wording (older advisories, 2016 to mid-2026)
_FLAT = re.compile(
    r"^(?P<name>.+?)\s+[–—-]\s+(?P<rule>(?:versions?|all|prior|before|toutes|multiples?|antérieures|v?\d).*)$", re.I
)


# A version line mentions a number or a version word. Alerts sometimes nest instructions instead
# ("Check macOS systems for ..."), and those must not become fake products.
_VERSIONISH = re.compile(
    r"\d+\.\d|\b(?:v|versions?|release|build|r)\s*\d|^(?:all|tous|toutes)\b|"
    r"\b(?:prior\s+to|before|multiple|multiples|antérieures?|all\s+versions|toutes\s+les\s+versions)\b",
    re.I,
)


def _rules(texts: list[str]) -> list[Rule]:
    out: list[Rule] = []
    for t in texts[:30]:
        if len(t) <= 160 and _VERSIONISH.search(t):
            out.extend(parse_rules(t))
    return out


def _looks_like_product(name: str) -> bool:
    """'GitLab', 'Grafana MCP Server': yes. 'If the malicious version of Nx Console is present:': no."""
    return 0 < len(name) <= 120 and not name.endswith((":", ".", "?")) and len(name.split()) <= 12


def _add(products: list[Product], name: str, rules: list[Rule]) -> None:
    if not rules or not _looks_like_product(name):
        return
    for p in products:  # the same product on several lines = several release lines of one product
        if p.name.lower() == name.lower():
            p.rules.extend(rules)
            return
    products.append(Product(name, rules))


def parse_body(html: str) -> tuple[list[Product], list[str], list[dict[str, str]], str]:
    """Products with their version rules, CVE ids, reference links and the intro sentence."""
    soup = BeautifulSoup(html or "", "html.parser")
    body = soup.select_one(".field--name-body") or soup
    products: list[Product] = []
    # Newer layout: <ul><li>Product<ul><li>Prior to 1.2</li></ul></li></ul>.
    # Older layout: <ul><li>Product – versions prior to 1.2</li></ul>.
    # Reference links live in a separate <ul class="list-unstyled"> and are skipped here.
    for ul in body.find_all("ul"):
        if "list-unstyled" in (ul.get("class") or []) or ul.find_parent("li") is not None:
            continue
        for li in ul.find_all("li", recursive=False):
            nested = li.find("ul")
            if nested is not None:
                name = clean(" ".join(str(t) for t in li.find_all(string=True, recursive=False)), 200)
                if name:
                    _add(products, name, _rules([clean(v.get_text(" "), 200) for v in nested.find_all("li")]))
            elif m := _FLAT.match(clean(li.get_text(" "), 400)):
                _add(products, clean(m.group("name"), 200), _rules([clean(m.group("rule"), 200)]))
        if len(products) >= 60:
            break
    text = body.get_text(" ")
    cves = list(dict.fromkeys(CVE_RE.findall(text + " " + " ".join(a.get("href", "") for a in body.find_all("a")))))
    refs = []
    for a in body.select("ul.list-unstyled a")[:15]:
        link = _safe_link(a.get("href"))
        if link:
            refs.append({"title": clean(a.get_text(" "), 160), "url": link})
    intro = ""
    for p in body.find_all("p"):
        t = clean(p.get_text(" "), 600)
        if t and not t.lower().startswith(("serial number", "numéro de série")):
            intro = t
            break
    return products, cves[:50], refs, intro


_TITLE_VENDOR = [
    re.compile(r"^(?:\[[^\]]*\]\s*)?(?P<v>.+?)\s+security\s+(?:advisor|bulletin|update)", re.I),
    re.compile(
        r"^(?:\[[^\]]*\]\s*)?(?:Avis|Bulletin|Mise à jour)s?\s+de\s+sécurité\s+"
        r"(?:de\s+la\s+|de\s+l'|du\s+|des\s+|de\s+|d')?(?P<v>.+?)\s*(?:\(|[–—]|$)",
        re.I,
    ),
]


def title_vendor(title: str) -> str:
    """'GitLab security advisory (AV26-1168)' -> 'gitlab'; 'Avis de sécurité de GitLab (AV26-1168)' -> 'gitlab'."""
    for pattern in _TITLE_VENDOR:
        if m := pattern.match(title):
            return norm_name(m.group("v"))[:60]
    return ""


def _serial(value: object) -> str:
    return clean(value, 24).replace("–", "-").replace("—", "-").replace(" ", "")


def _vendor(subject: object, title: str) -> str:
    """The title wins: the archive's subject tag is sometimes wrong (a GitHub incident tagged 'gitlab')."""
    if from_title := title_vendor(title):
        return from_title
    v = norm_name(clean(subject, 80)) if subject else ""
    return "" if v == "other" else v


def from_archive_item(item: dict, lang: str) -> Advisory | None:
    """One entry of /api/cccs/threats/v1/get (the archive behind the advisories page)."""
    serial = _serial(item.get("serial_number"))
    title = clean(item.get("title"), 300)
    if not SERIAL_RE.fullmatch(serial or "") and (m := SERIAL_RE.search(_serial(title).replace("(", " "))):
        serial = m.group(1)
    if not SERIAL_RE.fullmatch(serial or ""):
        return None
    body = item.get("body")
    html = "".join(body) if isinstance(body, list) else str(body or "")
    products, cves, refs, intro = parse_body(html)
    return Advisory(
        serial=serial,
        title=title,
        url=_safe_link(item.get("url")) or SITE,
        lang=lang,
        published=str(item.get("date_created") or item.get("date_modified") or "")[:10],
        vendor=_vendor(item.get("subject"), title),
        products=products,
        cves=cves,
        references=refs,
        intro=intro,
    )
