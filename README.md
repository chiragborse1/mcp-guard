# mcp-guard

`mcp-guard` is a Python CLI for finding leaked secrets in MCP and AI-agent project files before they reach GitHub.

It recursively scans a file or directory, pays special attention to MCP config files, masks every detected value, assigns severity levels, and exits non-zero when findings meet your configured threshold.

## What Is mcp-guard?

AI agents and MCP servers often need API keys in files such as `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, `.env`, and local config files. Those files are easy to commit by mistake.

`mcp-guard` gives you a lightweight pre-push or CI check for these leaks. It is designed for developer workflows, open-source projects, and portfolio repos where you want a readable terminal report plus machine-readable JSON for automation.

## Install

Install the latest version from GitHub with `pipx`:

```bash
pipx install git+https://github.com/chiragborse1/mcp-guard.git
```

PyPI publishing is planned. After the package is published, the install command will be:

```bash
pipx install mcp-guard
```

From a local checkout:

```bash
python -m pip install .
```

For local development:

```bash
python -m pip install -e ".[dev]"
```

## Usage

```bash
mcp-guard <path>
```

Examples:

```bash
mcp-guard .
mcp-guard ./mcp.json
mcp-guard . --fail-on high
mcp-guard --json .
mcp-guard . --sarif mcp-guard.sarif
mcp-guard . --staged
```

Exit codes:

- `0`: no findings at or above the configured failure severity
- `1`: findings exist at or above the configured failure severity
- `2`: scan could not run, such as a missing path

## Severity

Each finding has a severity:

- `high`: known credentials such as OpenAI, Anthropic, GitHub tokens, Postgres URLs, Supabase keys, and most provider API keys
- `medium`: generic secret assignments and lower-confidence sensitive values
- `low`: reserved for future lower-risk checks

By default, `mcp-guard` behaves as `--fail-on low`, so any finding exits `1`.

Use `--fail-on` to control CI strictness:

```bash
mcp-guard . --fail-on high
mcp-guard . --fail-on medium
mcp-guard . --fail-on low
```

For example, `--fail-on high` still prints medium findings, but exits `0` unless a high-severity finding exists.

## Staged Files

Use `--staged` to scan only files currently staged in Git:

```bash
mcp-guard . --staged
```

This is useful in pre-commit hooks because local untracked files and unstaged work are ignored.

Example pre-commit configuration:

```yaml
repos:
  - repo: local
    hooks:
      - id: mcp-guard
        name: mcp-guard
        entry: mcp-guard . --staged --fail-on high
        language: system
        pass_filenames: false
```

The same example is available at `examples/pre-commit/.pre-commit-config.yaml`.

## JSON Output

```bash
mcp-guard --json .
```

Example:

```json
{
  "root": "/path/to/project",
  "files_scanned": 3,
  "files_skipped": 0,
  "findings": [
    {
      "path": ".env",
      "line": 1,
      "column": 16,
      "kind": "OpenAI API key",
      "severity": "high",
      "masked_secret": "sk-p...7890",
      "context": "OPENAI_API_KEY=sk-p...7890",
      "is_mcp_config": false
    }
  ]
}
```

Secrets are masked in both text and JSON output.

## SARIF Output

Use SARIF when you want to upload findings to GitHub code scanning:

```bash
mcp-guard . --sarif mcp-guard.sarif
```

SARIF output includes rule metadata, severity-mapped levels, file locations, and masked values only. The command still prints normal terminal output and uses the same `--fail-on` exit-code behavior.

For a permissive code-scanning upload that records medium findings but only fails on high severity:

```bash
mcp-guard . --fail-on high --sarif mcp-guard.sarif
```

## Ignoring Files

Create a `.mcpguardignore` file in the scanned project root to ignore known-safe paths, such as test fixtures or intentionally unsafe examples.

Example:

```text
# Test fixtures intentionally use fake secrets.
tests/
examples/unsafe-mcp-config/
*.snapshot
```

When you scan a directory directly, `mcp-guard` reads that directory's own `.mcpguardignore`. This repo ignores `examples/unsafe-mcp-config/` during root scans, but you can still scan that folder directly.

For a single known-safe fake value, add an inline allow comment on the same line or the line immediately before it:

```text
# mcp-guard: allow - fake local fixture
OPENAI_API_KEY=sk-p...7890

ANTHROPIC_API_KEY=sk-a...7890 # mcp-guard: ignore
```

Use allow comments sparingly. Prefer `.mcpguardignore` for whole fixture directories.

## Example Scan

This repo includes fake unsafe files for testing:

```bash
mcp-guard examples/unsafe-mcp-config
```

Expected output includes masked fake findings:

```text
mcp-guard scanned 3 file(s) under /path/to/mcp-guard/examples/unsafe-mcp-config

Found 8 possible secret(s):
HIGH   .cursor/mcp.json:7:30 Firecrawl API key [MCP config] -> fc_f...7890
```

JSON:

```bash
mcp-guard --json examples/unsafe-mcp-config
```

## What It Detects

`mcp-guard` looks for:

- OpenAI and Anthropic API keys
- GitHub tokens
- Postgres connection URLs
- Supabase URLs and JWT-style keys
- Pinecone, Qdrant, Firecrawl, Brave Search, and Perplexity keys
- Generic `api_key`, `password`, `secret`, and `token` assignments

It gives special attention to MCP configuration files, including:

- `mcp.json`
- `claude_desktop_config.json`
- `.cursor/mcp.json`
- `.vscode/mcp.json`

The scanner skips `.git`, `node_modules`, `dist`, `build`, `.next`, `venv`, `.venv`, and `__pycache__`.

## GitHub Actions

Add this workflow to `.github/workflows/mcp-guard.yml`:

```yaml
name: mcp-guard

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install pipx
        run: python -m pip install --user pipx
      - name: Install mcp-guard
        run: pipx install git+https://github.com/chiragborse1/mcp-guard.git
      - name: Scan repository
        run: mcp-guard . --fail-on high
```

GitHub code scanning with SARIF upload:

```yaml
name: mcp-guard-sarif

on:
  pull_request:
  push:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install pipx
        run: python -m pip install --user pipx
      - name: Install mcp-guard
        run: pipx install git+https://github.com/chiragborse1/mcp-guard.git
      - name: Scan repository
        run: mcp-guard . --fail-on high --sarif mcp-guard.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-guard.sarif
```

You can also use the bundled composite action:

```yaml
name: mcp-guard-action

on:
  pull_request:

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: chiragborse1/mcp-guard/.github/actions/mcp-guard@v0.7.0
        with:
          path: "."
          fail-on: high
          sarif: mcp-guard.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-guard.sarif
```

For PR-only terminal scanning without SARIF:

```yaml
name: mcp-guard-pr

on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: chiragborse1/mcp-guard/.github/actions/mcp-guard@v0.7.0
        with:
          path: "."
          fail-on: high
```

## Development

Run tests:

```bash
uv run --extra dev pytest -q
```

Run the local CLI:

```bash
uv run --extra dev mcp-guard .
```

See `CONTRIBUTING.md` for contribution guidelines and `docs/RELEASE_CHECKLIST.md` for release steps.

Release history is tracked in `CHANGELOG.md`.

## License

MIT
