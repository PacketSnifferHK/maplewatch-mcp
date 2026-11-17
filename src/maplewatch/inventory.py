"""What you run: a stack file, CycloneDX SBOMs, and (optionally) live Docker containers.

Every location comes from environment variables set by whoever installs the server, never from
tool arguments. The model can't point maplewatch at an arbitrary file or host.
    MAPLEWATCH_STACK   path to stack.yaml (or .json)
    MAPLEWATCH_SBOM    comma-separated paths to CycloneDX JSON files
    MAPLEWATCH_DOCKER  "1" to read running containers (GET requests only)
    DOCKER_HOST        unix:///var/run/docker.sock (default) or tcp://socket-proxy:2375
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

from .text import clean, norm_name
from .versions import version_key

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ITEMS = 5000


@dataclass
class Software:
    name: str
    version: str | None
    source: str
    aliases: list[str] = field(default_factory=list)
    detail: str = ""

    def names(self) -> set[str]:
        return {n for n in (norm_name(x) for x in [self.name, *self.aliases]) if len(n) >= 3}

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "detail": self.detail,
            "comparable_version": version_key(self.version) is not None,
        }


def _read(path: str) -> str:
    p = Path(path).expanduser()
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{p.name} is larger than {MAX_FILE_BYTES // 1024 // 1024} MB")
    return p.read_text(encoding="utf-8")


def load_stack_file(path: str) -> list[Software]:
    """stack.yaml: either `software: [{name, version, aliases}]` or a plain `name: version` mapping."""
    data = yaml.safe_load(_read(path)) if not path.endswith(".json") else json.loads(_read(path))
    rows = data.get("software", data) if isinstance(data, dict) else data
    out: list[Software] = []
    if isinstance(rows, dict):
        rows = [{"name": k, "version": v} for k, v in rows.items()]
    for row in rows or []:
        if isinstance(row, dict) and row.get("name"):
            aliases = row.get("aliases") or []
            out.append(
                Software(
                    name=clean(row["name"], 120),
                    version=clean(row.get("version"), 60) or None,
                    source="stack file",
                    aliases=[clean(a, 120) for a in aliases if isinstance(a, str)][:10],
                )
            )
    return out[:MAX_ITEMS]


def load_sbom(path: str) -> list[Software]:
    """CycloneDX JSON (`syft -o cyclonedx-json`, `trivy --format cyclonedx`, ...)."""
    data = json.loads(_read(path))
    out = []
    for c in data.get("components", [])[:MAX_ITEMS]:
        if isinstance(c, dict) and c.get("name"):
            group = clean(c.get("group"), 80)
            out.append(
                Software(
                    name=clean(c["name"], 120),
                    version=clean(c.get("version"), 60) or None,
                    source="sbom",
                    aliases=[f"{group} {c['name']}"] if group else [],
                    detail=Path(path).name,
                )
            )
    return out


# ---------- Docker ----------
_VERSION_ENV = re.compile(r"^(?:([A-Z0-9_]+)_)?VERSION=(v?\d[\w.\-+]*)$")


def _image_names(image: str) -> tuple[str, list[str]]:
    """'lscr.io/linuxserver/radarr:5.2' -> ('radarr', ['linuxserver radarr'])."""
    repo = image.split("@")[0]
    if ":" in repo.rsplit("/", 1)[-1]:
        repo = repo.rsplit(":", 1)[0]
    parts = repo.split("/")
    if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
        parts = parts[1:]  # drop the registry host
    name = parts[-1] if parts else repo
    return name, [" ".join(parts)] if len(parts) > 1 else []


def _image_tag(image: str) -> str | None:
    last = image.split("@")[0].rsplit("/", 1)[-1]
    return last.rsplit(":", 1)[1] if ":" in last else None


def docker_client() -> httpx.Client:
    host = os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock")
    if host.startswith("unix://"):
        return httpx.Client(
            transport=httpx.HTTPTransport(uds=host[len("unix://") :]), base_url="http://docker", timeout=10.0
        )
    if host.startswith("tcp://"):
        return httpx.Client(base_url="http://" + host[len("tcp://") :], timeout=10.0)
    raise ValueError("DOCKER_HOST must be unix:// or tcp:// (point tcp at a read-only socket proxy)")


def discover_docker(client: httpx.Client) -> list[Software]:
    """Running containers. Only two GET endpoints are used: /containers/json and /images/{id}/json."""
    out: list[Software] = []
    containers = client.get("/containers/json").raise_for_status().json()
    seen: set[str] = set()
    for c in containers[:200]:
        image = clean(c.get("Image"), 200)
        image_id = str(c.get("ImageID", ""))
        if not image or image_id in seen or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            continue
        seen.add(image_id)
        info = client.get(f"/images/{image_id}/json").raise_for_status().json()
        config = info.get("Config") or {}
        labels = config.get("Labels") or {}
        name, aliases = _image_names(image)
        title = clean(labels.get("org.opencontainers.image.title"), 120)
        version, how = None, ""
        if v := clean(labels.get("org.opencontainers.image.version"), 60):
            version, how = v, "image label"
        if version is None:
            key = norm_name(name).replace(" ", "_").upper()
            for env in config.get("Env") or []:
                m = _VERSION_ENV.match(str(env)[:200])
                if m and (m.group(1) or "APP") in (key, "APP"):  # N8N_VERSION for n8n, APP_VERSION, VERSION
                    version, how = m.group(2), "env " + str(env).split("=", 1)[0]
                    break
        tag = _image_tag(image)
        if version is None and tag and version_key(tag) is not None:
            version, how = tag, "image tag"
        out.append(
            Software(
                name=title or name,
                version=version,
                source="docker",
                aliases=[name, *aliases] if title else aliases,
                detail=f"{image} (version from {how})" if version else f"{image} (no version found: pin a tag)",
            )
        )
    return out


def load_inventory() -> tuple[list[Software], list[str]]:
    """Everything configured, plus problems worth telling the user about."""
    items: list[Software] = []
    problems: list[str] = []
    if path := os.environ.get("MAPLEWATCH_STACK"):
        try:
            items += load_stack_file(path)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            problems.append(f"stack file: {exc}")
    for path in filter(None, (os.environ.get("MAPLEWATCH_SBOM") or "").split(",")):
        try:
            items += load_sbom(path.strip())
        except (OSError, ValueError) as exc:
            problems.append(f"SBOM {Path(path).name}: {exc}")
    if os.environ.get("MAPLEWATCH_DOCKER") == "1":
        try:
            with docker_client() as client:
                items += discover_docker(client)
        except (httpx.HTTPError, OSError, ValueError) as exc:
            problems.append(f"docker: {exc}")
    if not items and not problems:
        problems.append("nothing configured: set MAPLEWATCH_STACK, MAPLEWATCH_SBOM or MAPLEWATCH_DOCKER=1")
    return items[:MAX_ITEMS], problems
