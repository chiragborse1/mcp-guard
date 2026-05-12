# mcp-guard

`mcp-guard` is a small Python CLI that scans a file or directory for AI and MCP-related secrets before they get committed, shared, or uploaded.

It recursively scans files, skips common generated directories, highlights MCP config files, masks secret values in output, and exits with a non-zero status when possible secrets are found.

## Install

From this repository:

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
mcp-guard --json .
```

Exit codes:

- `0`: no secrets found
- `1`: possible secrets found
- `2`: scan could not run, such as a missing path

## Ignoring Files

Create a `.mcpguardignore` file in the scanned project root to ignore known-safe paths, such as test fixtures that intentionally contain fake secrets.

Example:

```text
# Test fixtures intentionally use fake secrets.
tests/
examples/unsafe-demo/
*.snapshot
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

## Output

Readable terminal output:

```text
mcp-guard scanned 3 file(s) under /path/to/project

Found 1 possible secret(s):
- .cursor/mcp.json:8:38 MCP config secret [MCP config] -> fc_a...3456
  context: mcpServers.firecrawl.env.FIRECRAWL_API_KEY
```

JSON output:

```bash
mcp-guard --json .
```

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
      "masked_secret": "sk-p...3456",
      "context": "OPENAI_API_KEY=sk-p...3456",
      "is_mcp_config": false
    }
  ]
}
```

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
      - name: Install mcp-guard
        run: python -m pip install .
      - name: Scan repository
        run: mcp-guard .
```

## Development

Run tests:

```bash
python -m pytest
```

## License

MIT
