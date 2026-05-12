from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re

from .scanner import ScanResult


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

SARIF_LEVELS = {
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def build_sarif(result: ScanResult) -> dict[str, object]:
    rules = {}
    sarif_results = []

    for finding in result.findings:
        rule_id = _rule_id(finding.kind)
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.kind,
            "shortDescription": {
                "text": finding.kind,
            },
            "fullDescription": {
                "text": f"mcp-guard detected a {finding.severity}-severity secret-like value.",
            },
            "properties": {
                "severity": finding.severity,
            },
        }
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVELS.get(finding.severity, "warning"),
                "message": {
                    "text": f"{finding.kind}: {finding.masked_secret}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.path.replace("\\", "/"),
                            },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "is_mcp_config": finding.is_mcp_config,
                    "context": finding.context,
                },
            }
        )

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-guard",
                        "informationUri": "https://github.com/chiragborse1/mcp-guard",
                        "semanticVersion": _package_version(),
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_sarif(result: ScanResult, output_path: Path) -> None:
    import json

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(build_sarif(result), indent=2), encoding="utf-8")


def _rule_id(kind: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", kind.lower()).strip("-")
    return f"mcp-guard.{normalized or 'secret'}"


def _package_version() -> str:
    for distribution in ("mcp-secrets-guard", "mcp-guard"):
        try:
            return version(distribution)
        except PackageNotFoundError:
            continue
    return "0.0.0"
