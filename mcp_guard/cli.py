from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import ScanError, scan_path

SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Scan files for AI and MCP-related secrets.",
    )
    parser.add_argument("path", help="File or directory to scan.")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON output.",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER),
        default="low",
        help="Exit 1 only when findings are at least this severity. Defaults to low.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = scan_path(Path(args.path))
    except ScanError as exc:
        if args.json_output:
            print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        else:
            print(f"mcp-guard: {exc}", file=sys.stderr)
        return 2

    if args.json_output:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_text(result)

    return 1 if _should_fail(result.findings, args.fail_on) else 0


def _print_text(result) -> None:
    print(f"mcp-guard scanned {result.files_scanned} file(s) under {result.root}")

    if result.files_skipped:
        print(f"Skipped {result.files_skipped} file(s)")

    if not result.findings:
        print("No secrets found.")
        return

    print("")
    print(f"Found {len(result.findings)} possible secret(s):")
    for finding in result.findings:
        marker = " [MCP config]" if finding.is_mcp_config else ""
        print(
            f"{finding.severity.upper():<6} {finding.path}:{finding.line}:{finding.column} "
            f"{finding.kind}{marker} -> {finding.masked_secret}"
        )
        if finding.context:
            print(f"  context: {finding.context}")

    print("")
    print("Review these values before committing or sharing this project.")


def _should_fail(findings, fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[finding.severity] >= threshold for finding in findings)


if __name__ == "__main__":
    raise SystemExit(main())
