# Changelog

All notable changes to `mcp-guard` are documented here.

## v1.0.0

- Added `mcp-guard --version`.
- Reduced duplicate MCP config findings by preferring provider-specific rules over generic matches.
- Finalized README demo output and public release documentation.

## v0.7.0

- Added a bundled composite GitHub Action wrapper.
- Added PR scanning examples for terminal output and SARIF upload.

## v0.6.0

- Added inline allow comments with `mcp-guard: allow` and `mcp-guard: ignore`.
- Reduced generic false positives for plain documentation URLs.

## v0.5.0

- Added packaging metadata polish for GitHub and future PyPI publishing.
- Added `CHANGELOG.md`, `CONTRIBUTING.md`, a release checklist, and issue templates.

## v0.4.0

- Added `--staged` mode for scanning only staged Git files.
- Added pre-commit hook documentation and an example config.

## v0.3.0

- Added SARIF output with `--sarif <path>`.
- Added GitHub code scanning documentation.
- Added SARIF structure tests.

## v0.2.0

- Added severity levels: `high`, `medium`, and `low`.
- Added `--fail-on high|medium|low`.
- Added severity to readable and JSON output.
- Added `examples/unsafe-mcp-config/` with fake secrets.
- Expanded tests and README documentation.

## v0.1.0

- Initial Python CLI package.
- Added recursive scanning, masking, JSON output, tests, CI, and MIT license.
