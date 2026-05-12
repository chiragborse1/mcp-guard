# Changelog

All notable changes to `mcp-guard` are documented here.

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
