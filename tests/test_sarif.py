import json
from pathlib import Path

from mcp_guard.cli import main
from mcp_guard.sarif import build_sarif
from mcp_guard.scanner import scan_path


def test_sarif_structure_contains_rules_results_and_masked_values(tmp_path: Path) -> None:
    sample = tmp_path / ".env"
    sample.write_text(
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        encoding="utf-8",
    )

    result = scan_path(tmp_path)
    sarif = build_sarif(result)

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-guard"
    assert run["tool"]["driver"]["rules"][0]["id"] == "mcp-guard.openai-api-key"
    assert run["results"][0]["ruleId"] == "mcp-guard.openai-api-key"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".env"
    assert "sk-p...3456" in run["results"][0]["message"]["text"]
    assert "abcdefghijklmnopqrstuvwxyz123456" not in json.dumps(sarif)


def test_cli_writes_sarif_file(tmp_path: Path, capsys) -> None:
    sample = tmp_path / ".env"
    output = tmp_path / "mcp-guard.sarif"
    sample.write_text(
        "BRAVE_SEARCH_API_KEY=brv_abcdefghijklmnopqrstuvwxyz123456",
        encoding="utf-8",
    )

    assert main([str(tmp_path), "--sarif", str(output)]) == 1

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"][0]["level"] == "error"
    assert "No secrets found." not in capsys.readouterr().out
