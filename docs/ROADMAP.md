# Roadmap

`mcp-guard` is now at its stable public portfolio release.

## Completed

- Recursive project scanning with generated-directory skips.
- MCP config awareness for `.cursor/mcp.json`, `.vscode/mcp.json`, `mcp.json`, and `claude_desktop_config.json`.
- Detection for common AI provider keys, GitHub tokens, Postgres URLs, Supabase keys, vector database keys, and generic assignments.
- Masked terminal, JSON, and SARIF output.
- Severity levels and configurable `--fail-on`.
- `.mcpguardignore`, inline allow comments, and staged-file scanning.
- GitHub Actions and pre-commit workflow examples.
- Tests, CI, changelog, contributing guide, release checklist, and issue templates.
- PyPI publishing as `mcp-secrets-guard`.

## Possible Future Work

- More provider-specific detectors as MCP ecosystems evolve.
- Optional baseline files for existing known findings.
- Additional config formats such as TOML-aware and YAML-aware parsing.
- Homebrew, Docker, or standalone binary distribution if demand appears.
