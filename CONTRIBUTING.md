# Contributing

Thanks for helping. maplewatch is small on purpose: read-only, one data source, honest about uncertainty.
Contributions that keep it that way are very welcome.

## Getting set up

```bash
git clone https://github.com/PacketSnifferHK/maplewatch-mcp && cd maplewatch-mcp
uv venv && uv pip install -e ".[dev]"
pytest && ruff check src tests && ruff format --check src tests
```

`pytest` never touches the network. `MAPLEWATCH_LIVE=1 pytest -m live` checks the parser against today's real advisories.

## Good first issues

- **A version phrasing maplewatch reports as "can't tell"** but a human can read. Add the real sentence to the
  table in `tests/test_versions.py` first, then make it pass in `src/maplewatch/versions.py`.
- **A new inventory source:** Proxmox (`pveversion`), Kubernetes images, `dpkg -l`, Homebrew. Same rules as
  the existing ones: location from an environment variable, read-only, size-limited.
- **Output formats** for `--report`: Markdown, JSON, SARIF.

## Rules of the road

- **No write, exec or network tools.** If a feature needs one, open an issue first so we can talk about it.
- **No guessing.** When the data is ambiguous, the answer is "check" with a reason.
- **Tests with real wording.** Paste the real advisory phrase (with its serial in a comment), not an invented one.
- **Security-relevant changes** update the table in `SECURITY.md`.
- One logical change per pull request, with a short description of the user-visible effect.
