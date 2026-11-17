"""Which advisories touch which software you run, and how sure we are."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .advisories import Advisory, Product
from .inventory import Software
from .text import norm_name
from .versions import evaluate

Confidence = Literal["exact", "likely", "possible"]


def _contains(haystack: str, needle: str) -> bool:
    """Whole-word match: 'grafana' is in 'grafana enterprise', not in 'grafanalib'."""
    return f" {needle} " in f" {haystack} "


def name_match(sw: Software, product: Product, advisory: Advisory) -> Confidence | None:
    prod = norm_name(product.name)
    vendor = advisory.vendor
    names = sw.names()
    if prod in names or (vendor and f"{vendor} {prod}" in names):
        return "exact"
    for n in names:
        if vendor and n == vendor and advisory.kind == "advisory":
            return "likely"  # e.g. software 'roundcube', advisory by Roundcube for product 'Webmail'
        if _contains(prod, n):
            return "likely" if vendor and (_contains(n, vendor) or _contains(vendor, n)) else "possible"
    return None


@dataclass
class Finding:
    status: Literal["affected", "check"]
    software: Software
    advisory: Advisory
    product: Product
    confidence: Confidence
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "software": self.software.name,
            "installed_version": self.software.version,
            "found_in": self.software.source,
            "advisory": self.advisory.serial,
            "title": self.advisory.title,
            "published": self.advisory.published,
            "product_in_advisory": self.product.name,
            "affected_versions": [r.raw for r in self.product.rules][:10],
            "name_match": self.confidence,
            "why": self.reason,
            "url": self.advisory.url,
        }


def check(software: list[Software], advisories: list[Advisory]) -> tuple[list[Finding], int]:
    """Findings (affected or needs a human look) and how many name matches were ruled out by version."""
    findings: list[Finding] = []
    ruled_out = 0
    for adv in advisories:
        for sw in software:
            best: Finding | None = None
            for product in adv.products:
                conf = name_match(sw, product, adv)
                if conf is None:
                    continue
                verdict, reason = evaluate(sw.version, product.rules)
                if verdict == "not_affected":
                    ruled_out += 1
                    continue
                status = "affected" if verdict == "affected" and conf != "possible" else "check"
                if conf == "possible":
                    reason = f"name only partly matches '{product.name}'. {reason}"
                f = Finding(status, sw, adv, product, conf, reason)
                if best is None or (f.status == "affected" and best.status != "affected"):
                    best = f
            if best:
                findings.append(best)
    findings.sort(key=lambda f: f.advisory.published, reverse=True)  # newest first...
    findings.sort(key=lambda f: f.status != "affected")  # ...with confirmed hits on top (sort is stable)
    return findings, ruled_out
