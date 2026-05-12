from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import json
import os
from pathlib import Path
import re
from typing import Iterable


SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "venv",
    ".venv",
    "__pycache__",
}

MCP_CONFIG_NAMES = {
    "mcp.json",
    "claude_desktop_config.json",
}

MCP_CONFIG_SUFFIXES = {
    os.path.join(".cursor", "mcp.json"),
    os.path.join(".vscode", "mcp.json"),
}

MAX_FILE_BYTES = 2 * 1024 * 1024
IGNORE_FILE_NAME = ".mcpguardignore"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    column: int
    kind: str
    severity: str
    masked_secret: str
    context: str
    is_mcp_config: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "kind": self.kind,
            "severity": self.severity,
            "masked_secret": self.masked_secret,
            "context": self.context,
            "is_mcp_config": self.is_mcp_config,
        }


@dataclass(frozen=True)
class ScanResult:
    root: str
    files_scanned: int
    files_skipped: int
    findings: list[Finding]

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class ScanError(Exception):
    """Raised when a requested scan cannot be performed."""


@dataclass(frozen=True)
class SecretPattern:
    kind: str
    severity: str
    regex: re.Pattern[str]
    secret_group: str = "secret"


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags | re.IGNORECASE)


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("OpenAI API key", "high", re.compile(r"(?P<secret>sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,})")),
    SecretPattern("Anthropic API key", "high", re.compile(r"(?P<secret>sk-ant-[A-Za-z0-9_-]{20,})")),
    SecretPattern("GitHub token", "high", re.compile(r"(?P<secret>gh[pousr]_[A-Za-z0-9_]{20,})")),
    SecretPattern("Postgres URL", "high", re.compile(r"(?P<secret>postgres(?:ql)?://[^\s'\"<>]+)", re.IGNORECASE)),
    SecretPattern("Supabase URL", "medium", re.compile(r"(?P<secret>https://[a-z0-9-]+\.supabase\.co)", re.IGNORECASE)),
    SecretPattern("Supabase anon/service key", "high", re.compile(r"(?P<secret>eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})")),
    SecretPattern("Pinecone API key", "high", _compile(r"['\"]?\b(?:pinecone(?:_api)?_key|PINECONE_API_KEY)\b['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9_-]{16,})")),
    SecretPattern("Qdrant API key", "high", _compile(r"['\"]?\b(?:qdrant(?:_api)?_key|QDRANT_API_KEY)\b['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9_-]{16,})")),
    SecretPattern("Firecrawl API key", "high", _compile(r"['\"]?\b(?:firecrawl(?:_api)?_key|FIRECRAWL_API_KEY)\b['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9_-]{16,})")),
    SecretPattern("Brave Search API key", "high", _compile(r"['\"]?\b(?:brave(?:_search)?(?:_api)?_key|BRAVE_SEARCH_API_KEY)\b['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9_-]{16,})")),
    SecretPattern("Perplexity API key", "high", _compile(r"['\"]?\b(?:perplexity(?:_api)?_key|PPLX_API_KEY|PERPLEXITY_API_KEY)\b['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9_-]{16,})")),
    SecretPattern(
        "Generic secret assignment",
        "medium",
        _compile(
            r"['\"]?\b(?:[A-Za-z0-9_-]*(?:api[_-]?key|secret|password|passwd|pwd|token|access[_-]?token|auth[_-]?token)[A-Za-z0-9_-]*)\b['\"]?"
            r"\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9][A-Za-z0-9_./+=:@-]{11,})"
        ),
    ),
)

MCP_SECRET_KEYS = {
    "api_key",
    "apikey",
    "api-key",
    "key",
    "token",
    "access_token",
    "auth_token",
    "password",
    "secret",
}


def scan_path(path: Path, include_files: Iterable[Path] | None = None) -> ScanResult:
    root = path.expanduser().resolve()
    if not root.exists():
        raise ScanError(f"path does not exist: {path}")

    ignore_patterns = _load_ignore_patterns(root)
    findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0

    file_paths = include_files if include_files is not None else _iter_files(root)
    for file_path in file_paths:
        file_path = file_path.expanduser().resolve()
        if not file_path.exists() or not file_path.is_file():
            files_skipped += 1
            continue

        rel_path = _display_path(file_path, root)
        if _is_ignored(rel_path, ignore_patterns):
            files_skipped += 1
            continue

        if _should_skip_file(file_path):
            files_skipped += 1
            continue

        try:
            text = _read_text(file_path)
        except (OSError, UnicodeDecodeError):
            files_skipped += 1
            continue

        files_scanned += 1
        is_mcp_config = _is_mcp_config(file_path)
        findings.extend(_scan_text(text, rel_path, is_mcp_config))
        if is_mcp_config:
            findings.extend(_scan_mcp_json(text, rel_path))

    findings = _dedupe_findings(findings)
    findings.sort(key=lambda item: (item.path, item.line, item.column, item.kind))
    return ScanResult(
        root=str(root),
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        findings=findings,
    )


def _iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return

    for current_root, dir_names, file_names in os.walk(root):
        dir_names[:] = [name for name in dir_names if name not in SKIP_DIRS]
        for file_name in file_names:
            yield Path(current_root) / file_name


def _should_skip_file(path: Path) -> bool:
    try:
        return path.stat().st_size > MAX_FILE_BYTES
    except OSError:
        return True


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_ignore_patterns(root: Path) -> tuple[str, ...]:
    if root.is_file():
        ignore_file = root.parent / IGNORE_FILE_NAME
    else:
        ignore_file = root / IGNORE_FILE_NAME

    try:
        lines = ignore_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()

    patterns: list[str] = []
    for line in lines:
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        patterns.append(pattern)
    return tuple(patterns)


def _is_ignored(rel_path: str, patterns: tuple[str, ...]) -> bool:
    normalized = rel_path.replace(os.sep, "/")
    parts = normalized.split("/")

    for pattern in patterns:
        normalized_pattern = pattern.replace(os.sep, "/").lstrip("./")
        if not normalized_pattern:
            continue

        if normalized_pattern.endswith("/"):
            directory = normalized_pattern.rstrip("/")
            if directory in parts or normalized.startswith(f"{directory}/"):
                return True
            continue

        if "/" in normalized_pattern:
            if fnmatch.fnmatch(normalized, normalized_pattern):
                return True
            continue

        if fnmatch.fnmatch(Path(normalized).name, normalized_pattern):
            return True
        if any(fnmatch.fnmatch(part, normalized_pattern) for part in parts):
            return True

    return False


def _display_path(path: Path, root: Path) -> str:
    if root.is_file():
        return path.name
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _is_mcp_config(path: Path) -> bool:
    normalized = os.path.normpath(str(path))
    if path.name in MCP_CONFIG_NAMES:
        return True
    return any(normalized.endswith(suffix) for suffix in MCP_CONFIG_SUFFIXES)


def _scan_text(text: str, rel_path: str, is_mcp_config: bool) -> list[Finding]:
    findings: list[Finding] = []
    seen_spans: set[tuple[int, int, str]] = set()

    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            secret = match.group(pattern.secret_group).rstrip("',\")]} \t\r\n")
            if not _looks_like_secret(secret):
                continue
            if pattern.kind == "Generic secret assignment" and not _looks_like_generic_secret(secret):
                continue

            start, end = match.span(pattern.secret_group)
            if _has_allow_comment(text, start):
                continue

            dedupe_key = (start, end, pattern.kind)
            if dedupe_key in seen_spans:
                continue
            seen_spans.add(dedupe_key)

            line, column = _line_column(text, start)
            findings.append(
                Finding(
                    path=rel_path,
                    line=line,
                    column=column,
                    kind=pattern.kind,
                    severity=pattern.severity,
                    masked_secret=mask_secret(secret),
                    context=_line_context(text, start, secret),
                    is_mcp_config=is_mcp_config,
                )
            )

    return findings


def _scan_mcp_json(text: str, rel_path: str) -> list[Finding]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for key_path, value in _walk_json(parsed):
        if not isinstance(value, str) or not _looks_like_secret(value):
            continue

        key = key_path[-1].lower() if key_path else ""
        if key not in MCP_SECRET_KEYS and not any(token in key for token in MCP_SECRET_KEYS):
            continue

        value_offset = text.find(value)
        if _has_allow_comment(text, value_offset if value_offset >= 0 else 0):
            continue

        line, column = _line_column(text, value_offset if value_offset >= 0 else 0)
        findings.append(
            Finding(
                path=rel_path,
                line=line,
                column=column,
                kind="MCP config secret",
                severity="high",
                masked_secret=mask_secret(value),
                context=".".join(key_path),
                is_mcp_config=True,
            )
        )

    return findings


def _walk_json(value, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for item_key, item_value in value.items():
            yield from _walk_json(item_value, path + (str(item_key),))
    elif isinstance(value, list):
        for index, item_value in enumerate(value):
            yield from _walk_json(item_value, path + (str(index),))
    else:
        yield path, value


def _looks_like_secret(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 12:
        return False
    if stripped.lower() in {"changeme", "your_api_key", "your-api-key", "example", "password"}:
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", stripped) and all(
        len(part) <= 16 for part in stripped.split(".")
    ):
        return False
    return True


def _looks_like_generic_secret(value: str) -> bool:
    stripped = value.strip().lower()
    if stripped.startswith(("http://", "https://")):
        return False
    return True


def _has_allow_comment(text: str, offset: int) -> bool:
    current_line = _line_at_offset(text, offset).lower()
    previous_line = _previous_line_at_offset(text, offset).lower()
    return _is_allow_comment(current_line) or _is_allow_comment(previous_line)


def _is_allow_comment(line: str) -> bool:
    return "mcp-guard: allow" in line or "mcp-guard: ignore" in line


def _line_at_offset(text: str, offset: int) -> str:
    offset = max(offset, 0)
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end]


def _previous_line_at_offset(text: str, offset: int) -> str:
    offset = max(offset, 0)
    current_start = text.rfind("\n", 0, offset) + 1
    if current_start <= 1:
        return ""
    previous_end = current_start - 1
    previous_start = text.rfind("\n", 0, previous_end) + 1
    return text[previous_start:previous_end]


def _line_column(text: str, offset: int) -> tuple[int, int]:
    offset = max(offset, 0)
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def _line_context(text: str, offset: int, secret: str) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].strip()
    line = line.replace(secret, mask_secret(secret))
    return line[:160]


def mask_secret(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}...{secret[-4:]}"


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, int, int, str, str]] = set()
    for finding in findings:
        if finding.kind == "MCP config secret":
            key = (finding.path, finding.line, finding.column, finding.masked_secret, finding.kind)
        else:
            key = (finding.path, finding.line, finding.column, finding.masked_secret, "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
