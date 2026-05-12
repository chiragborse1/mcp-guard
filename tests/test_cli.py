import json
from pathlib import Path

from mcp_guard.cli import main


def test_cli_returns_zero_when_clean(tmp_path: Path, capsys) -> None:
    (tmp_path / "README.md").write_text("no secrets here", encoding="utf-8")

    assert main([str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "No secrets found." in output


def test_cli_returns_one_and_masks_secret(tmp_path: Path, capsys) -> None:
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        encoding="utf-8",
    )

    assert main([str(tmp_path)]) == 1

    output = capsys.readouterr().out
    assert "OpenAI API key" in output
    assert "sk-p...3456" in output
    assert "abcdefghijklmnopqrstuvwxyz123456" not in output


def test_cli_json_output(tmp_path: Path, capsys) -> None:
    (tmp_path / ".env").write_text(
        "BRAVE_SEARCH_API_KEY=brv_abcdefghijklmnopqrstuvwxyz123456",
        encoding="utf-8",
    )

    assert main(["--json", str(tmp_path)]) == 1

    payload = json.loads(capsys.readouterr().out)
    assert payload["files_scanned"] == 1
    assert payload["findings"][0]["kind"] == "Brave Search API key"
    assert payload["findings"][0]["masked_secret"] == "brv_...3456"

