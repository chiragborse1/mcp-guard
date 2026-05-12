from pathlib import Path


def test_github_action_metadata_exists() -> None:
    action = Path(__file__).parents[1] / ".github" / "actions" / "mcp-guard" / "action.yml"

    text = action.read_text(encoding="utf-8")

    assert "using: composite" in text
    assert "mcp-guard" in text
    assert "fail-on" in text
    assert "sarif" in text
