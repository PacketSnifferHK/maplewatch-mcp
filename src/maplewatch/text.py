"""Turning untrusted text into safe, bounded strings.

Everything that reaches the model from the internet (advisory titles, product names, vendor
link text) goes through `clean()`. It removes markup and invisible characters and caps the
length, so a hostile string can't hide instructions or flood the context window.
"""

from __future__ import annotations

import re
import unicodedata

# Zero-width and bidirectional-override characters are invisible but change how text is read.
_INVISIBLE = dict.fromkeys([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])
_TAGS = re.compile(r"<[^>]*>")
_SPACE = re.compile(r"\s+")


def clean(value: object, limit: int = 300) -> str:
    """Plain text: no HTML tags, no control or invisible characters, single spaces, at most `limit` chars."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value))
    text = _TAGS.sub(" ", text).translate(_INVISIBLE)
    text = "".join(ch if ch.isprintable() or ch == " " else " " for ch in text)
    text = _SPACE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def norm_name(value: str) -> str:
    """Lowercase name with punctuation flattened to single spaces: 'mcp-Grafana' -> 'mcp grafana'."""
    text = unicodedata.normalize("NFKD", value.lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return _SPACE.sub(" ", re.sub(r"[^a-z0-9]+", " ", text)).strip()
