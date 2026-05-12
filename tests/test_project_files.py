from pathlib import Path


def test_github_action_metadata_exists() -> None:
    action = Path(__file__).parents[1] / ".github" / "actions" / "mcp-guard" / "action.yml"

    text = action.read_text(encoding="utf-8")

    assert "using: composite" in text
    assert "mcp-guard" in text
    assert "fail-on" in text
    assert "sarif" in text


def test_publish_workflow_uses_trusted_publishing() -> None:
    workflow = Path(__file__).parents[1] / ".github" / "workflows" / "publish.yml"

    text = workflow.read_text(encoding="utf-8")

    assert "pypa/gh-action-pypi-publish@release/v1" in text
    assert "id-token: write" in text
    assert "environment:" in text
    assert "name: pypi" in text
    assert "mcp-secrets-guard" in text
