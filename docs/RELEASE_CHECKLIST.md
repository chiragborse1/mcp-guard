# Release Checklist

Use this checklist before tagging a release.

## Preflight

- Confirm `README.md` matches current CLI behavior.
- Confirm `CHANGELOG.md` includes the new version.
- Confirm no real secrets are present in examples, docs, tests, or fixtures.
- Confirm generated files are not staged.

## Verification

```bash
uv run --extra dev pytest -q
uv run --extra dev mcp-guard .
uv run --extra dev mcp-guard --json .
uv run --extra dev mcp-guard examples/unsafe-mcp-config
uv run --extra dev mcp-guard --json examples/unsafe-mcp-config
```

The root scan should be clean. The unsafe example scan should report only masked fake secrets.

## Version And Tag

1. Update `pyproject.toml`.
2. Update `CHANGELOG.md`.
3. Commit the release changes.
4. Tag the release.
5. Push `main` and tags.

```bash
git tag vX.Y.Z
git push origin main --tags
```

## PyPI

The PyPI distribution name is `mcp-secrets-guard`; the CLI command remains `mcp-guard`.

Publishing uses PyPI Trusted Publishing through `.github/workflows/publish.yml`.

Before publishing:

- Confirm the PyPI project has a trusted publisher configured.
- Confirm the GitHub environment is named `pypi`.
- Confirm the workflow filename is `publish.yml`.
- Publish a GitHub Release for the tag you want to publish.
