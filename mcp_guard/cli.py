from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version
import json
import subprocess
import sys
from pathlib import Path

from .scanner import ScanError, scan_path
from .sarif import write_sarif

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
        "--version",
        action="version",
        version=f"mcp-guard {_package_version()}",
    )
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
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        help="Write SARIF output to PATH for GitHub code scanning.",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan only staged Git files under the requested path.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    scan_root = Path(args.path)

    try:
        staged_files = _staged_files(scan_root) if args.staged else None
        result = scan_path(scan_root, include_files=staged_files)
    except (ScanError, GitError) as exc:
        if args.json_output:
            print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        else:
            print(f"mcp-guard: {exc}", file=sys.stderr)
        return 2

    if args.sarif:
        try:
            write_sarif(result, Path(args.sarif))
        except OSError as exc:
            print(f"mcp-guard: could not write SARIF file: {exc}", file=sys.stderr)
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


class GitError(Exception):
    """Raised when staged-file discovery cannot run."""


def _staged_files(path: Path) -> list[Path]:
    scan_root = path.expanduser().resolve()
    git_root = _git_root(scan_root)
    completed = subprocess.run(
        ["git", "-C", str(git_root), "diff", "--cached", "--name-only", "--diff-filter=ACMRT"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "could not list staged files"
        raise GitError(detail)

    staged: list[Path] = []
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        candidate = (git_root / line).resolve()
        if _is_under_scan_root(candidate, scan_root):
            staged.append(candidate)
    return staged


def _git_root(path: Path) -> Path:
    start = path if path.is_dir() else path.parent
    completed = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "not a Git repository"
        raise GitError(detail)
    return Path(completed.stdout.strip()).resolve()


def _is_under_scan_root(candidate: Path, scan_root: Path) -> bool:
    if scan_root.is_file():
        return candidate == scan_root
    try:
        candidate.relative_to(scan_root)
    except ValueError:
        return False
    return True


def _package_version() -> str:
    try:
        return version("mcp-guard")
    except PackageNotFoundError:
        return "0.0.0"


if __name__ == "__main__":
    raise SystemExit(main())
