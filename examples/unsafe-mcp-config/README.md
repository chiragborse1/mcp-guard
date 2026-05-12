# Unsafe MCP Config Example

This folder intentionally contains fake secrets so you can see what `mcp-guard` reports.

Run:

```bash
mcp-guard examples/unsafe-mcp-config
```

For JSON output:

```bash
mcp-guard --json examples/unsafe-mcp-config
```

These values are fake and safe for documentation. The repository root `.mcpguardignore` ignores this folder so `mcp-guard .` can stay clean, but scanning this folder directly still reports the example findings.
