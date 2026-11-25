# Changelog

## 0.1.2 (2026-11-25)

- Fixed a false "affected": a range whose end looks mistyped (fewer parts than its start and a leading zero,
  such as "Version 13.0.0 to 13.08" in AV26-936, which Grafana's own advisory gives as 13.0.8) was read as
  13.8 and marked Grafana 13.3.0 as affected. It is now reported as "check" with the original text.
  Across the whole archive this changes that one rule and no others.

## 0.1.1 (2026-11-25)

- **Fixed a missed hit.** When an advisory lists fixes for several release lines, a version on a line with no
  fix of its own (usually an end-of-life line) was reported as not affected. Example: AV26-1200 lists n8n fixes
  for 2.48, 2.49 and 2.50, and 0.1.0 ruled out n8n 2.45.7, which is affected. Such versions are now affected,
  with the reason "no fix for its release line". Found by running maplewatch on a real homelab. Across the
  archive this turns about 2,000 version checks from "not affected" to "affected" or "check"; none go the
  other way.
- When two fixes are listed for the same line (2.49.4 and 2.49.5), the later one counts.
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
