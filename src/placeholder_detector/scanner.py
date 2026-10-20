from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

IGNORED_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__"}
TEXT_EXTENSIONS = {".css", ".go", ".html", ".java", ".js", ".jsx", ".json", ".md", ".php", ".py", ".rb", ".rs", ".scss", ".sh", ".sql", ".swift", ".toml", ".ts", ".tsx", ".vue", ".xml", ".yaml", ".yml"}


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    severity: str
    message: str
    pattern: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    severity: str
    message: str
    path: str
    line: int
    excerpt: str
    evidence_sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


RULES = (
    Rule("unfinished-marker", "warning", "Unresolved work marker", re.compile(r"\b(?:TODO|FIXME|HACK|XXX)\b", re.I)),
    Rule("placeholder-copy", "error", "Placeholder copy is visible", re.compile(r"\b(?:lorem ipsum|placeholder text|your (?:company|name) here)\b", re.I)),
    Rule("example-domain", "warning", "Example domain remains in project content", re.compile(r"https?://(?:www\.)?(?:example\.com|example\.org|test\.com)\b", re.I)),
    Rule("empty-link", "error", "Link target is empty or a hash placeholder", re.compile(r"href\s*=\s*[\"'](?:#|javascript:void\(0\)|)[\"']", re.I)),
    Rule("not-implemented", "error", "Runtime path explicitly reports unimplemented behavior", re.compile(r"(?:NotImplementedError|throw new Error\([\"']not implemented|http_response_code\(501\))", re.I)),
    Rule("fake-data-label", "warning", "Content is explicitly marked as fake or sample data", re.compile(r"\b(?:fake|dummy|mock|sample)[_-]?(?:user|customer|testimonial|data)s?\b", re.I)),
    Rule("coming-soon", "warning", "Coming-soon copy may represent unfinished scope", re.compile(r"\bcoming soon\b", re.I)),
    Rule("empty-handler", "warning", "Empty callback or handler body", re.compile(r"(?:onClick|onSubmit|onclick)\s*=\s*\{?\s*(?:\(.*?\)|\w+)?\s*=>\s*\{\s*\}\s*}?", re.I)),
    Rule("stub-return", "warning", "Function appears to return a fixed empty collection", re.compile(r"\breturn\s+(?:\[\]|\{\}|null)\s*;?\s*(?://.*)?$", re.I)),
)


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[Finding, ...]
    skipped: tuple[dict[str, str], ...]


def scan(root: Path, excludes: tuple[str, ...] = (), minimum: str = "info") -> tuple[Finding, ...]:
    """Return findings only; use scan_report for completeness evidence."""
    return scan_report(root, excludes, minimum).findings


def scan_report(root: Path, excludes: tuple[str, ...] = (), minimum: str = "info") -> ScanResult:
    selected = root.expanduser().absolute()
    if any(path.is_symlink() for path in (selected, *selected.parents)):
        raise ValueError("Scan root must not contain symlink components")
    target = selected.resolve()
    if not target.is_dir():
        raise ValueError(f"Not a directory: {target}")
    allowed = {"info": 0, "warning": 1, "error": 2}
    if minimum not in allowed:
        raise ValueError("Invalid minimum severity")
    threshold = allowed[minimum]
    findings: list[Finding] = []
    skipped: list[dict[str, str]] = []

    def excluded(relative: str) -> bool:
        return any(fnmatch.fnmatch(relative, pattern) for pattern in excludes)

    def unreadable(error: OSError) -> None:
        path = Path(error.filename) if error.filename else target
        try:
            relative = path.relative_to(target).as_posix()
        except ValueError:
            relative = "."
        skipped.append({"path": relative, "reason": "unreadable-directory"})

    for directory, directories, files in os.walk(target, followlinks=False, onerror=unreadable):
        parent = Path(directory)
        kept = []
        for name in sorted(directories):
            path = parent / name
            relative = path.relative_to(target).as_posix()
            if name in IGNORED_DIRECTORIES or excluded(relative):
                continue
            if path.is_symlink():
                skipped.append({"path": relative, "reason": "symlink-directory"})
            else:
                kept.append(name)
        directories[:] = kept
        for name in sorted(files):
            path = parent / name
            relative = path.relative_to(target).as_posix()
            if path.suffix.casefold() not in TEXT_EXTENSIONS or excluded(relative):
                continue
            if path.is_symlink():
                skipped.append({"path": relative, "reason": "symlink-file"})
                continue
            try:
                if not path.is_file():
                    skipped.append({"path": relative, "reason": "non-regular-file"})
                    continue
                with path.open("rb") as handle:
                    content = handle.read(2_000_001)
                if len(content) > 2_000_000:
                    skipped.append({"path": relative, "reason": "size-limit"})
                    continue
                lines = content.decode("utf-8").splitlines()
            except UnicodeDecodeError:
                skipped.append({"path": relative, "reason": "invalid-utf8"})
                continue
            except OSError:
                skipped.append({"path": relative, "reason": "unreadable-file"})
                continue
            for number, line in enumerate(lines, 1):
                if "placeholder-detector: ignore" in line:
                    continue
                for rule in RULES:
                    if allowed[rule.severity] >= threshold and rule.pattern.search(line):
                        findings.append(Finding(rule.id, rule.severity, rule.message, relative, number, _redact(line), hashlib.sha256(" ".join(line.strip().split()).encode("utf-8")).hexdigest()))
    findings.sort(key=lambda item: (-allowed[item.severity], item.path, item.line, item.rule))
    skipped.sort(key=lambda item: (item["path"], item["reason"]))
    return ScanResult(tuple(findings), tuple(skipped))


def _redact(line: str) -> str:
    compact = " ".join(line.strip().split())
    compact = re.sub(
        r'''(?i)((?:password|secret|token|api[_-]?key)["']?)(\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*(?:"|\\?$)|'(?:[^'\\]|\\.)*(?:'|\\?$)|[^\s,;]+)''',
        r"\1\2[redacted]",
        compact,
    )
    return compact[:180] + ("…" if len(compact) > 180 else "")
