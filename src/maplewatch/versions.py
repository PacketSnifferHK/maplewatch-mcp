"""Affected-version rules as the Cyber Centre writes them, and checking an installed version against them.

Real phrasings from the feed and archive (English and French):
    "Prior to 19.5.6"               / "Versions antérieures à la version 19.5.6"        -> v < X
    "Prior to or equal to 1.0.0"    / "Versions antérieures jusqu'à la version 1.0.0"  -> v <= X
    "Version 22.7R2.5 and prior"    / "Version 4.2 et versions antérieures"             -> v <= X
    "Versions 6.8p1 to 9.9p1"       / "De la version 2.0 à 2.4"                         -> X <= v <= Y
    "Versions 0.123.0 to versions prior to 1.121.3"                                     -> X <= v < Y
    "15.x versions prior to 15.2.3" / "versions 3.15.x prior to 3.15.2"                 -> on 15.x, v < Y
    "Versions 8.0, 8.1 and 8.2"     / "Version 1.02"                                    -> exactly these
    "All versions"                  / "Toutes les versions"                             -> every version
Anything else ("Multiple versions", firmware build names, ...) is kept as text and reported as
"can't tell". The checker never guesses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Verdict = Literal["affected", "not_affected", "unknown"]
Version = tuple[int, ...]

# A version token: optional v, a dotted number, then any suffix (-M1, p1, R2.5, .x, -8035 ...).
# Only the dotted number is compared; the suffix is kept in the raw text for humans.
# The quantifiers are possessive (*+, ++): the number and the suffix can't trade characters,
# which keeps matching linear. Without that, matching was quadratic (ReDoS): 8,000 hostile characters took ~3 s.
VER = r"[vV]?(\d++(?:\.\d++)*+)[\w.\-+~]*+"
# Vendor schemes where the suffix carries real version information: 22.7R2.5, 6.8p1, 11.0.0-M1, 8.0.0-8035.
_FUZZY = re.compile(r"\d(?:[.\-]?[A-Za-z]{1,3}\.?\d|-\d)")
MAX_RULE_CHARS = 200
_AND = r"(?:and|et)"


@dataclass(frozen=True)
class Rule:
    kind: Literal["lt", "le", "range", "exact", "all", "unknown"]
    raw: str
    upper: Version | None = None
    lower: Version | None = None
    branch: Version | None = None
    upper_inclusive: bool = True
    values: tuple[Version, ...] = field(default=())
    fuzzy: bool = False

    def bounds(self) -> list[Version]:
        return [b for b in (self.upper, self.lower, *self.values) if b is not None]


def version_key(text: str | None) -> Version | None:
    """'v1.40.0.0' -> (1, 40, 0, 0); '11.0.0-M1' -> (11, 0, 0). None for 'latest' and other non-numbers."""
    if not text:
        return None
    m = re.match(r"\s*[vV]?(\d+(?:\.\d+)*)", text[:200])
    if not m or any(len(p) > 12 for p in m.group(1).split(".")):
        return None  # not a version; also keeps int() away from enormous digit strings
    return tuple(int(p) for p in m.group(1).split("."))


def _cmp(a: Version, b: Version) -> int:
    n = max(len(a), len(b))
    a2, b2 = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a2 > b2) - (a2 < b2)


def _on_line(v: Version, line: Version) -> bool:
    """Is v on release line `line`? (19.5.2 is on 19.5; 19 counts as 19.0.)"""
    padded = v + (0,) * max(0, len(line) - len(v))
    return padded[: len(line)] == line


def _k(text: str) -> Version:
    return version_key(text) or (0,)


_E = re.IGNORECASE
_RULES: list[tuple[re.Pattern[str], str]] = [
    # order matters: the longer phrasings first
    (re.compile(rf"^(?:versions?\s+)?prior\s+to\s+or\s+equal\s+to\s+{VER}", _E), "le"),
    (re.compile(rf"^versions?\s+antérieures\s+jusqu'?à\s+(?:la\s+)?version\s+{VER}", _E), "le"),
    (re.compile(rf"^(?:versions?\s+)?{VER}\s+(?:and\s+(?:prior|earlier)|et\s+versions?\s+antérieures)\b", _E), "le"),
    (re.compile(rf"^versions?\s+{VER}\s+to\s+versions?\s+(?:prior\s+to|before)\s+{VER}", _E), "range_lt"),
    (re.compile(rf"^(?:versions?\s+)?{VER}\s+(?:versions?\s+)?(?:prior\s+to|before)\s+{VER}", _E), "branch"),
    (re.compile(rf"^(?:versions?\s+)?{VER}\s+versions?\s+antérieures\s+à\s+(?:la\s+)?version\s+{VER}", _E), "branch"),
    (re.compile(rf"^(?:versions?\s+)?(?:prior\s+to|before)\s+{VER}", _E), "lt"),
    (re.compile(rf"^versions?\s+antérieures\s+à\s+(?:la\s+)?(?:version\s+)?{VER}", _E), "lt"),
    (re.compile(rf"^(?:versions?\s+)?{VER}\s+(?:to|through)\s+{VER}\s*$", _E), "range"),
    (re.compile(rf"^(?:de\s+la\s+)?versions?\s+{VER}\s+à\s+{VER}\s*$", _E), "range"),
]
_ALL = re.compile(r"^(all\s+versions?|toutes\s+les\s+versions)\s*\.?$", _E)
_EXACT = re.compile(rf"^(?:versions?\s+)?{VER}(?:\s*,\s*{VER})*(?:\s*,?\s*{_AND}\s+{VER})?\s*$", _E)


def parse_rule(text: str) -> Rule:
    raw = " ".join(text.split())[:MAX_RULE_CHARS]
    if _ALL.match(raw):
        return Rule("all", raw)
    rule = _parse(raw)
    if rule.kind != "unknown" and _FUZZY.search(raw):
        return Rule(rule.kind, raw, rule.upper, rule.lower, rule.branch, rule.upper_inclusive, rule.values, True)
    return rule


def _looks_mistyped(lower: str, upper: str) -> bool:
    """'13.0.0 to 13.08': the end of a range has fewer parts than its start and a leading zero. Almost
    certainly a typo for 13.0.8, and reading it as 13.8 would mark 13.3.0 as affected. Don't guess."""
    parts = upper.split(".")
    return len(parts) < len(lower.split(".")) and any(len(x) > 1 and x.startswith("0") for x in parts)


def _parse(raw: str) -> Rule:
    for pattern, kind in _RULES:
        m = pattern.match(raw)
        if not m:
            continue
        texts = [g for g in m.groups() if g]
        if kind in ("range", "range_lt") and len(texts) == 2 and _looks_mistyped(*texts):
            return Rule("unknown", raw)
        keys = [version_key(g) for g in texts]
        if any(k is None for k in keys):
            return Rule("unknown", raw)
        nums = [k for k in keys if k is not None]
        if kind == "branch":
            return Rule("lt", raw, upper=nums[1], branch=nums[0])
        if kind == "range_lt":
            return Rule("range", raw, lower=nums[0], upper=nums[1], upper_inclusive=False)
        if kind == "range":
            return Rule("range", raw, lower=nums[0], upper=nums[1])
        return Rule(kind, raw, upper=nums[0])  # type: ignore[arg-type]
    if _EXACT.match(raw):
        keys = [version_key(t) for t in re.findall(VER, raw)]
        if all(keys):
            return Rule("exact", raw, values=tuple(k for k in keys if k))
    return Rule("unknown", raw)


_LT_PREFIX = re.compile(r"^(?:versions?\s+)?(?:prior\s+to|before|antérieures\s+à(?:\s+la)?(?:\s+version)?)\s+", _E)
_LIST_SEP = re.compile(
    r"\s*(?:,|\band\b|\bet\b)\s*(?:(?:versions?\s+)?(?:prior\s+to|before|antérieures\s+à(?:\s+la)?(?:\s+version)?)\s+)?",
    _E,
)
_PIECE = re.compile(rf"^{VER}(?:\s*\([^)]{{0,40}}\))?$")


def parse_rules(text: str) -> list[Rule]:
    """Like parse_rule, but splits release-line lists into one rule per line:
    'versions prior to 12.4.2, 12.3.6, 12.2.8 and 11.6.14' -> four 'prior to' rules."""
    raw = " ".join(text.split())[:MAX_RULE_CHARS]
    if m := _LT_PREFIX.match(raw):
        pieces = [x for x in _LIST_SEP.split(raw[m.end() :]) if x]
        if len(pieces) > 1 and all(_PIECE.match(x) and version_key(x) for x in pieces):
            fuzzy = bool(_FUZZY.search(raw))
            return [Rule("lt", raw, upper=_k(x), fuzzy=fuzzy) for x in pieces[:20]]
    return [parse_rule(raw)]


def _hit(v: Version, r: Rule) -> bool:
    if r.kind == "lt" and r.upper is not None:
        return (r.branch is None or _on_line(v, r.branch)) and _cmp(v, r.upper) < 0
    if r.kind == "le" and r.upper is not None:
        return _cmp(v, r.upper) <= 0
    if r.kind == "range" and r.lower is not None and r.upper is not None:
        top = _cmp(v, r.upper)
        return _cmp(v, r.lower) >= 0 and (top <= 0 if r.upper_inclusive else top < 0)
    if r.kind == "exact":
        # "version 8.0" means the 8.0 line; "version 8.0.0-8035" means that build
        return any(_on_line(v, x) if len(x) <= 2 else _cmp(v, x) == 0 for x in r.values)
    return False


def _common(a: Version, b: Version) -> int:
    n = 0
    for x, y in zip(a, b, strict=False):
        if x != y:
            break
        n += 1
    return n


def _fmt(v: Version) -> str:
    return ".".join(map(str, v))


def _release_line_verdict(installed: str | None, v: Version, uppers: list[Version]) -> tuple[Verdict, str]:
    """Several "prior to" fixes = maintained release lines (GitLab: 19.3.9 / 19.4.8 / 19.5.6).

    Compare with the fixes that share the most of your version, up to major.minor:
      * same major.minor  -> the newest fix on that line (two fixes on one line: the later one wins)
      * same major only   -> your minor has no fix of its own: affected unless newer than every fix in your major
      * no shared major   -> affected unless newer than every fix
    The newest fix is used because an advisory can bundle several issues fixed in different patches.
    """
    depth = min(2, max(_common(v, u) for u in uppers))
    same = [u for u in uppers if _common(v, u) >= depth]
    top = max(same, key=lambda u: u + (0,) * (8 - len(u)))
    line = _fmt(v[:depth]) + ".x" if depth else ""
    if _cmp(v, top) < 0:
        if depth == 2:
            return "affected", f"{installed} is on the {line} line, fixed in {_fmt(top)}"
        if depth == 1:
            return "affected", f"{installed}: no fix for its release line; the {line} fixes go up to {_fmt(top)}"
        return "affected", f"{installed} is older than the fixed releases (newest fix {_fmt(top)})"
    if depth == 2:
        return "not_affected", f"{installed} already has the {line} fix ({_fmt(top)})"
    return "not_affected", f"{installed} is newer than every listed fix for its release line ({_fmt(top)})"


def evaluate(installed: str | None, rules: list[Rule]) -> tuple[Verdict, str]:
    """Is `installed` inside any of one product's rules? Returns (verdict, plain-language reason).

    Several plain "prior to" bounds on one product usually mean maintained release lines
    (GitLab: prior to 19.3.9 / 19.4.8 / 19.5.6). A version on one of those lines is checked against
    that line's fix; older than every line is affected; newer than every line is not.
    """
    if not rules:
        return "unknown", "the advisory lists no versions for this product"
    if any(r.kind == "all" for r in rules):
        return "affected", "the advisory says all versions are affected"
    v = version_key(installed)
    if v is None:
        return "unknown", f"installed version {installed or 'unknown'!r} can't be compared; pin a real version"
    readable = [r for r in rules if r.kind != "unknown"]
    unreadable = [r.raw for r in rules if r.kind == "unknown"]

    lines = [r for r in readable if r.kind == "lt" and r.branch is None and r.upper is not None]
    if len(lines) > 1:
        verdict = _release_line_verdict(installed, v, [r.upper for r in lines if r.upper])
        if verdict[0] == "affected":
            return verdict
        readable = [r for r in readable if r not in lines]
        if not readable and not unreadable:
            return verdict

    for r in readable:
        if r.fuzzy and any(_on_line(v, b) for b in r.bounds()):
            return "unknown", (
                f"{installed} is too close to call: the vendor's own version scheme in {r.raw!r} "
                "can't be compared reliably; check the vendor advisory"
            )
        if _hit(v, r):
            return "affected", f"{installed} matches {r.raw!r}"
    if unreadable:
        return "unknown", f"{installed} is outside the readable rules, but these aren't machine-readable: " + "; ".join(
            unreadable
        )
    return "not_affected", f"{installed} is outside every affected range"
