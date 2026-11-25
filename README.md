# maplewatch 🍁

**Which Canadian Cyber Centre security advisories actually affect the software you run?**

The Canadian Centre for Cyber Security published over 1,190 advisories in 2026 alone, three or four
every day. Nobody can read them all. maplewatch is an [MCP](https://modelcontextprotocol.io) server
(and a small CLI) that checks every advisory against your own stack: a short YAML file, your SBOMs,
or your running Docker containers. It tells you which ones hit you, which version fixes them, and why.

<!-- mcp-name: io.github.PacketSnifferHK/maplewatch-mcp -->

> **Unofficial.** maplewatch is not affiliated with or endorsed by the Canadian Centre for Cyber
> Security, the Communications Security Establishment, or the Government of Canada. It reads their
> public advisories and links back to each one. Always confirm on the linked advisory before acting.

```text
$ maplewatch-mcp --report
maplewatch 0.1.1: 1304 Cyber Centre advisories since 2025-11-17, 8 pieces of software checked

AFFECTED AV26-1168  GitLab 19.5.5  (GitLab) 19.5.5 is on the 19.5.x line, fixed in 19.5.6
         https://www.cyber.gc.ca/en/alerts-advisories/gitlab-security-advisory-av26-1168
AFFECTED AV26-285   Grafana 12.2.0  (Grafana) 12.2.0 is on the 12.2.x line, fixed in 12.2.8
         https://www.cyber.gc.ca/en/alerts-advisories/grafana-security-advisory-av26-285
AFFECTED AV26-1075  Roundcube 1.6.14  (Roundcube Webmail) 1.6.14 is on the 1.6.x line, fixed in 1.6.20
         https://www.cyber.gc.ca/en/alerts-advisories/roundcube-security-advisory-av26-1075
CHECK    AV26-584   n8n 1.120.4  (n8n (Credential Exfiltration)) ... these aren't machine-readable: multiple versions
...
58 name matches ruled out by version.
```
*(Output from [`examples/stack.example.yaml`](examples/stack.example.yaml), shortened.)*

## What it does

- **Reads the whole archive.** Every advisory since 2016 comes from the same public endpoint cyber.gc.ca's
  own advisories page uses, plus the Atom feed for anything published in the last few minutes. Both English and French.
- **Understands how advisories describe versions.** "Prior to 19.5.6", "versions 0.123.0 to versions prior
  to 1.121.3", "15.x versions prior to 15.2.3", "Versions antérieures à la version 3.1.2, 3.0.9 et 2.9.14", and
  maintained release lines: GitLab 19.4.7 is checked against the 19.4 fix, not the 19.5 one, and a release
  line with no fix of its own (usually end-of-life) counts as affected.
- **Never guesses.** When the advisory says "multiple versions", when a vendor uses its own scheme
  (`22.7R2.5`), or when your image is `:latest`, the answer is **check**, with the reason. It doesn't
  invent a yes or a no.
- **Read-only, everywhere.** No tool writes, executes or deletes anything. See [SECURITY.md](SECURITY.md).

## Quick start

1. List what you run (or skip this and use Docker discovery or SBOMs, below):

   ```yaml
   # ~/maplewatch/stack.yaml
   software:
     - name: GitLab
       version: 19.5.5
     - name: Roundcube
       version: 1.6.14
       aliases: [Roundcube Webmail]
   ```

2. Try it from a terminal (needs [uv](https://docs.astral.sh/uv/)):

   ```bash
   MAPLEWATCH_STACK=~/maplewatch/stack.yaml uvx maplewatch-mcp --report          # English
   MAPLEWATCH_STACK=~/maplewatch/stack.yaml uvx maplewatch-mcp --report --lang fr  # français
   ```

3. Add it to your MCP client (Claude Desktop shown; any MCP client works):

   ```json
   {
     "mcpServers": {
       "maplewatch": {
         "command": "uvx",
         "args": ["maplewatch-mcp"],
         "env": { "MAPLEWATCH_STACK": "/Users/you/maplewatch/stack.yaml" }
       }
     }
   }
   ```

   Then ask: *"Which Cyber Centre advisories affect my stack this year?"*

`--report` exits with **0** when nothing is affected, **1** when something is, and **2** when nothing could be
checked (no inventory found), so a cron job or n8n workflow can alert on it.

The first run downloads the archive (about 2 MB compressed) and takes about 10 seconds. After that it starts
from a local cache in under a second.

## Tools

| Tool | What it answers |
|---|---|
| `maplewatch_check_stack` | Which advisories affect my software? (`days`: look-back window, default 365) |
| `maplewatch_latest` | The newest alerts and advisories, optionally for one vendor |
| `maplewatch_search` | Every advisory since 2016 mentioning a product, vendor or CVE id |
| `maplewatch_get` | One advisory in detail: affected products and versions, CVEs, vendor links |
| `maplewatch_my_stack` | What maplewatch thinks you run, and which entries can't be compared |

All five are marked `readOnlyHint: true`. Everything takes a `lang` of `en` or `fr`.

## What you run: three sources

| Source | Turn it on with | Notes |
|---|---|---|
| Stack file | `MAPLEWATCH_STACK=/path/stack.yaml` | `software: [{name, version, aliases}]` or a plain `name: version` map |
| SBOMs | `MAPLEWATCH_SBOM=/path/a.json,/path/b.json` | CycloneDX JSON from `syft`, `trivy`, ... |
| Docker | `MAPLEWATCH_DOCKER=1` | Reads the version from image labels, `<APP>_VERSION` env vars, or the tag |

For Docker, point `DOCKER_HOST` at a **read-only socket proxy** instead of the raw socket. See
[`examples/docker-compose.socket-proxy.yaml`](examples/docker-compose.socket-proxy.yaml).

**About `:latest`:** an image tagged `latest` with no version label has no version maplewatch can compare,
so it can only ever say "check". Pinning image versions is good practice anyway: you can't patch what you
can't identify.

## How a verdict is reached

1. **Name match.** *exact* (`GitLab` = `GitLab`), *likely* (the advisory's vendor is the software you
   listed, e.g. Roundcube's advisory for "Webmail"), or *possible* (your name is only part of the product name).
2. **Version check** against the advisory's affected versions.
3. **Result.** **affected** = a confident name match and a version inside an affected range. **check** = a
   human should look. A match ruled out by version is counted, not shown.

## Data and fair use

- Advisory data © Government of Canada (Communications Security Establishment), used under its
  [terms](https://www.cse-cst.gc.ca/en/about-apropos/terms-and-conditions) for non-commercial reproduction with
  attribution. Every result carries the source and a link to the original advisory.
- Polite by design: the archive is fetched at most once a day, the feed at most every 15 minutes, with an
  identifying User-Agent. If the site is down, maplewatch serves its cache and says so.
- No telemetry. Nothing about your stack leaves your machine; the only outbound requests go to `www.cyber.gc.ca`.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
pytest                               # offline suite, no network
MAPLEWATCH_LIVE=1 pytest -m live     # against the real cyber.gc.ca
ruff check src tests && ruff format --check src tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues: more version phrasings, more inventory sources
(Proxmox, Kubernetes, `dpkg -l`), and output formats (Markdown, SARIF).

## License

MIT for the code. Advisory content belongs to the Government of Canada; see *Data and fair use*.
