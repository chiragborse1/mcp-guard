# Contributing

Thanks for helping improve `mcp-guard`.

## Development Setup

```bash
git clone https://github.com/chiragborse1/mcp-guard.git
cd mcp-guard
uv run --extra dev pytest -q
```

Run the local CLI:

```bash
uv run --extra dev mcp-guard .
```

## Safety Rules

- Do not use real secrets in issues, tests, examples, screenshots, or docs.
- Keep fake test values obviously fake.
- Do not print full detected secret values in terminal output, JSON, SARIF, logs, or test failures.
- Keep examples ignored from root scans when they intentionally contain fake secrets.

## Pull Requests

Before opening a PR:

```bash
uv run --extra dev pytest -q
uv run --extra dev mcp-guard .
uv run --extra dev mcp-guard --json .
```

For scanner changes, add tests for both true positives and likely false positives.

## Release Notes

Update `CHANGELOG.md` when user-facing behavior changes.
