import json
from pathlib import Path
import subprocess

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
    assert "HIGH" in output
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
    assert payload["findings"][0]["severity"] == "high"
    assert payload["findings"][0]["masked_secret"] == "brv_...3456"


def test_cli_fail_on_high_returns_zero_for_medium_only_findings(tmp_path: Path, capsys) -> None:
    (tmp_path / "config.json").write_text(
        '{"password": "correct-horse-battery-staple"}',
        encoding="utf-8",
    )

    assert main([str(tmp_path), "--fail-on", "high"]) == 0

    output = capsys.readouterr().out
    assert "MEDIUM" in output
    assert "correct-horse-battery-staple" not in output


def test_cli_fail_on_medium_returns_one_for_medium_findings(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        '{"password": "correct-horse-battery-staple"}',
        encoding="utf-8",
    )

    assert main([str(tmp_path), "--fail-on", "medium"]) == 1


def test_cli_default_returns_one_for_any_finding(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        '{"password": "correct-horse-battery-staple"}',
        encoding="utf-8",
    )

    assert main([str(tmp_path)]) == 1


def test_cli_staged_scans_only_staged_files(tmp_path: Path, capsys) -> None:
    _git(tmp_path, "init")
    staged = tmp_path / ".env"
    unstaged = tmp_path / "local.env"
    staged.write_text(
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        encoding="utf-8",
    )
    unstaged.write_text(
        "ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz123456",
        encoding="utf-8",
    )
    _git(tmp_path, "add", ".env")

    assert main([str(tmp_path), "--staged"]) == 1

    output = capsys.readouterr().out
    assert ".env" in output
    assert "OpenAI API key" in output
    assert "Anthropic API key" not in output


def test_cli_staged_returns_zero_when_no_files_are_staged(tmp_path: Path, capsys) -> None:
    _git(tmp_path, "init")
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        encoding="utf-8",
    )

    assert main([str(tmp_path), "--staged"]) == 0

    output = capsys.readouterr().out
    assert "scanned 0 file(s)" in output
    assert "No secrets found." in output


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)
