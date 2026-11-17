import json

import httpx
import pytest

from maplewatch.inventory import discover_docker, docker_client, load_inventory, load_sbom, load_stack_file

SHA = "sha256:" + "a" * 64
SHA2 = "sha256:" + "b" * 64
SHA3 = "sha256:" + "c" * 64


def test_stack_file_both_formats(tmp_path):
    long = tmp_path / "long.yaml"
    long.write_text("software:\n  - name: GitLab\n    version: 19.5.5\n    aliases: [gitlab-ce]\n")
    short = tmp_path / "short.yaml"
    short.write_text("grafana: 12.2.0\nforgejo: latest\n")
    a = load_stack_file(str(long))
    b = load_stack_file(str(short))
    assert (a[0].name, a[0].version, a[0].aliases) == ("GitLab", "19.5.5", ["gitlab-ce"])
    assert [(s.name, s.version) for s in b] == [("grafana", "12.2.0"), ("forgejo", "latest")]
    assert b[1].as_dict()["comparable_version"] is False


def test_stack_file_is_not_executed(tmp_path):
    evil = tmp_path / "evil.yaml"
    evil.write_text("!!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(Exception):  # noqa: B017  # yaml.safe_load refuses it
        load_stack_file(str(evil))


def test_sbom(tmp_path):
    f = tmp_path / "bom.json"
    f.write_text(
        json.dumps(
            {
                "components": [
                    {"name": "openssl", "version": "3.0.13", "group": ""},
                    {"name": "log4j-core", "version": "2.14.1", "group": "org.apache.logging.log4j"},
                ]
            }
        )
    )
    items = load_sbom(str(f))
    assert [(s.name, s.version) for s in items] == [("openssl", "3.0.13"), ("log4j-core", "2.14.1")]
    assert items[1].aliases == ["org.apache.logging.log4j log4j-core"]


def test_docker_discovery_reads_labels_env_and_tags():
    containers = [
        {"Image": "grafana/grafana:latest", "ImageID": SHA},
        {"Image": "docker.n8n.io/n8nio/n8n:latest", "ImageID": SHA2},
        {"Image": "codeberg.org/forgejo/forgejo:11.0.3", "ImageID": SHA3},
        {"Image": "evil", "ImageID": "../../etc/passwd"},  # bad ids are never requested
    ]
    images = {
        SHA: {"Config": {"Labels": {"org.opencontainers.image.version": "12.2.0"}, "Env": []}},
        SHA2: {"Config": {"Labels": {}, "Env": ["NODE_VERSION=22.1.0", "N8N_VERSION=1.120.4"]}},
        SHA3: {"Config": {"Labels": {}, "Env": []}},
    }
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path == "/containers/json":
            return httpx.Response(200, json=containers)
        return httpx.Response(200, json=images[request.url.path.split("/")[2]])

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    found = {s.name: s for s in discover_docker(client)}
    assert found["grafana"].version == "12.2.0" and "image label" in found["grafana"].detail
    assert found["n8n"].version == "1.120.4"  # N8N_VERSION, not NODE_VERSION
    assert found["forgejo"].version == "11.0.3"
    assert all(m == "GET" for m, _ in seen)
    assert not any("passwd" in p for _, p in seen)


def test_docker_host_must_be_unix_or_tcp(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "ssh://root@server")
    with pytest.raises(ValueError):
        docker_client()


def test_nothing_configured_explains_itself(monkeypatch):
    for var in ("MAPLEWATCH_STACK", "MAPLEWATCH_SBOM", "MAPLEWATCH_DOCKER"):
        monkeypatch.delenv(var, raising=False)
    items, problems = load_inventory()
    assert items == [] and "MAPLEWATCH_STACK" in problems[0]


def test_missing_file_is_a_problem_not_a_crash(monkeypatch, tmp_path):
    monkeypatch.setenv("MAPLEWATCH_STACK", str(tmp_path / "nope.yaml"))
    items, problems = load_inventory()
    assert items == [] and problems and "stack file" in problems[0]
