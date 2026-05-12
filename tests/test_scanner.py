from pathlib import Path

from mcp_guard.scanner import scan_path


def test_scan_detects_ai_and_database_secrets(tmp_path: Path) -> None:
    sample = tmp_path / ".env"
    sample.write_text(
        "\n".join(
            [
                "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
                "ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz123456",
                "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456",
                "DATABASE_URL=postgresql://user:pass@example.com:5432/app",
                "SUPABASE_URL=https://project-ref.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY=eyJaaaaaaaaaaaaaaaaaaaaaa.eyJbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccc",
                "PINECONE_API_KEY=pc_abcdefghijklmnopqrstuvwxyz",
            ]
        ),
        encoding="utf-8",
    )

    result = scan_path(tmp_path)
    kinds = {finding.kind for finding in result.findings}

    assert result.files_scanned == 1
    assert "OpenAI API key" in kinds
    assert "Anthropic API key" in kinds
    assert "GitHub token" in kinds
    assert "Postgres URL" in kinds
    assert "Supabase URL" in kinds
    assert "Supabase anon/service key" in kinds
    assert "Pinecone API key" in kinds
    assert all("abcdefghijklmnopqrstuvwxyz123456" not in finding.masked_secret for finding in result.findings)


def test_scan_skips_ignored_directories(tmp_path: Path) -> None:
    ignored = tmp_path / "node_modules"
    ignored.mkdir()
    (ignored / "package.js").write_text(
        "const token = 'sk-proj-abcdefghijklmnopqrstuvwxyz123456';",
        encoding="utf-8",
    )
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')", encoding="utf-8")

    result = scan_path(tmp_path)

    assert result.files_scanned == 1
    assert result.findings == []


def test_scan_flags_mcp_config_values(tmp_path: Path) -> None:
    cursor = tmp_path / ".cursor"
    cursor.mkdir()
    config = cursor / "mcp.json"
    config.write_text(
        """
        {
          "mcpServers": {
            "firecrawl": {
              "command": "npx",
              "env": {
                "FIRECRAWL_API_KEY": "fc_abcdefghijklmnopqrstuvwxyz123456"
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )

    result = scan_path(tmp_path)

    assert any(finding.is_mcp_config for finding in result.findings)
    assert any(finding.kind == "MCP config secret" for finding in result.findings)
    assert all("fc_abcdefghijklmnopqrstuvwxyz123456" not in finding.masked_secret for finding in result.findings)


def test_scan_detects_quoted_json_key_assignments(tmp_path: Path) -> None:
    sample = tmp_path / "config.json"
    sample.write_text(
        """
        {
          "QDRANT_API_KEY": "qd_abcdefghijklmnopqrstuvwxyz123456",
          "password": "correct-horse-battery-staple"
        }
        """,
        encoding="utf-8",
    )

    result = scan_path(tmp_path)
    kinds = {finding.kind for finding in result.findings}

    assert "Qdrant API key" in kinds
    assert "Generic secret assignment" in kinds
    assert all("correct-horse-battery-staple" not in finding.context for finding in result.findings)


def test_scan_single_file_uses_file_name(tmp_path: Path) -> None:
    sample = tmp_path / "settings.toml"
    sample.write_text(
        'perplexity_api_key = "pplx_abcdefghijklmnopqrstuvwxyz123456"',
        encoding="utf-8",
    )

    result = scan_path(sample)

    assert result.files_scanned == 1
    assert result.findings[0].path == "settings.toml"
    assert result.findings[0].line == 1
