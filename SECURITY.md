# Security

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security tab → *Report a vulnerability*). Don't open
a public issue. You'll get a reply within 7 days. maplewatch has no servers or user data of its own; the
realistic risks are in what it reads and what it returns to a model, described below.

## Threat model

maplewatch sits between three things it doesn't control: **a model** that calls its tools, **the internet**
(advisory text), and **your machine** (files and Docker). The design rule: maplewatch only reads, and only
from places the person who installed it chose.

### What it can and can't do

| Can | Can't |
|---|---|
| HTTPS GET to `www.cyber.gc.ca` (two endpoints) | Contact any other host, including after a redirect |
| Read the stack file and SBOMs named in its environment | Read a path a model asks for: no tool takes a path or URL |
| `GET /containers/json` and `GET /images/{sha256}/json` on Docker, if enabled | Start, stop, exec or change anything in Docker |
| Write its own cache (one JSON file per language) | Write anywhere else, or run commands |

### Threats and mitigations

| # | Threat | Mitigation | Tested in |
|---|---|---|---|
| 1 | **Prompt injection via advisory text.** A product name or vendor link title says "ignore previous instructions…". Advisory text is written by vendors and copied by the Cyber Centre, so it can't be fully trusted. | All internet text goes through `clean()`: HTML stripped; zero-width and bidi-override characters removed; length capped (product names 200 chars). It's returned in labelled data fields, and the server instructions tell the model it's data. There is **no tool that could act** on an injected instruction: every tool is read-only. | `test_server.py::test_prompt_injection_in_advisory_text_stays_data` |
| 2 | **SSRF / data exfiltration.** A model is tricked into making maplewatch fetch an attacker's URL. | No tool accepts a URL or path. Advisories are looked up by validated serial (`^[A-Z]{2}\d{2}-\d{1,5}$`). An httpx request hook rejects every request, redirects included, that isn't `https://www.cyber.gc.ca`. | `test_sources.py::test_redirects_off_site_are_blocked`, `::test_only_https_cyber_centre_is_allowed`, `test_server.py::test_bad_input_is_rejected` |
| 3 | **Arbitrary file read.** A model asks to "check the stack at /etc/shadow". | Inventory locations come only from environment variables set at install time. Files over 5 MB are refused. YAML is parsed with `safe_load` (no object construction). | `test_inventory.py::test_stack_file_is_not_executed` |
| 4 | **Docker socket = root.** The raw socket allows anything. | Only two GET endpoints, image ids validated as `sha256:<64 hex>`, and the docs recommend a read-only socket proxy with `POST=0`. | `test_inventory.py::test_docker_discovery_reads_labels_env_and_tags` |
| 5 | **ReDoS.** Hostile advisory text with a long run of version numbers freezes the parser. | **Found in development:** an early version regex backtracked quadratically: 8,000 characters of hostile input took about 3 s. Fixed with possessive quantifiers (about 0.1 ms for the same input) plus a 200-char cap per rule. Digit strings over 12 characters are never converted to integers. | `test_versions.py::test_no_catastrophic_backtracking` |
| 6 | **Oversized or malformed responses.** | 60 MB response cap while streaming, 30 s timeout, `defusedxml` for the Atom feed, and an unexpected archive shape is an error, not a crash. | `test_sources.py::test_response_size_cap` |
| 7 | **Wrong answers that look confident.** A bad "not affected" is worse than no tool. | Uncertainty is a first-class result: unreadable wording, vendor version schemes near a boundary, `:latest` images and partial name matches all become **check**, with the reason. The archive's vendor tag is overridden by the title because it's sometimes wrong (a GitHub incident tagged "gitlab"). Every finding links to the official advisory. | `test_versions.py` (40+ real phrasings), `test_matcher.py::test_mislabelled_alert_does_not_match` |
| 8 | **Stale data during an outage.** | The disk cache is served with an explicit warning in every response. With no cache, the tool returns a clear error instead of an empty "all clear". | `test_sources.py::test_disk_cache_survives_restart_and_offline`, `test_server.py::test_data_outage_is_a_clear_tool_error` |
| 9 | **Supply chain.** | Every GitHub Action is pinned to a commit SHA. PyPI releases use trusted publishing (no stored token). The `mcp-publisher` binary is verified with cosign before use. gitleaks runs on every push. Dependencies have upper bounds. | CI |
| 10 | **Misrepresenting the government.** | "Unofficial" appears in the package description, README, server instructions and every tool response. No government name or symbol in the project name, and no logo. | — |

### Out of scope

- The correctness of the Cyber Centre's advisories themselves.
- A compromised machine running maplewatch (it runs with the user's own permissions).
- Model behaviour outside maplewatch's tools: an MCP client that lets a model run shell commands is a risk
  regardless of maplewatch.
