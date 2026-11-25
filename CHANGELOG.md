# Changelog

## 0.1.1 (2026-11-25)

- Fixed: when no software could be found (for example Docker unreachable), `--report` printed
  "Nothing in this window affects the software listed", which read like an all-clear. It now says
  NOTHING WAS CHECKED and exits with code 2; the MCP tool returns `nothing_checked: true`.
- `--report` exit codes for cron and n8n: 0 = nothing affected, 1 = something affected, 2 = nothing could be checked.
- Inventory problems (such as an unreachable Docker) are shown at the top of the report, not buried at the end.

## 0.1.0 (2026-11-25)

First release.

- Five read-only MCP tools: `maplewatch_check_stack`, `maplewatch_latest`, `maplewatch_search`, `maplewatch_get`,
  `maplewatch_my_stack`. English and French.
- Data: the full Cyber Centre advisory archive (2016 onwards) plus the Atom feed, cached on disk
  (archive daily, feed every 15 minutes), with an offline fallback.
- Version rules: "prior to", "prior to or equal to", "and prior", ranges, release lines (`15.x versions prior to
  15.2.3`), lists of fixes per release line, exact versions, "all versions", in English and French.
  Vendor version schemes near a boundary are reported as "check".
- Inventory: stack file (YAML/JSON), CycloneDX SBOMs, Docker (labels, `<APP>_VERSION`, tags) through
  a read-only socket proxy.
- `maplewatch-mcp --report` for terminals, cron and n8n.
- Security: host allowlist incl. redirects, no path/URL tool arguments, text sanitising, ReDoS-safe parsing,
  response size cap, threat model in SECURITY.md.
