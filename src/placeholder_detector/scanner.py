from __future__ import annotations

import fnmatch
import hashlib
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


def scan(root: Path, excludes: tuple[str, ...] = (), minimum: str = "info") -> tuple[Finding, ...]:
    target = root.expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"Not a directory: {target}")
    allowed = {"info": 0, "warning": 1, "error": 2}
    threshold = allowed[minimum]
    findings: list[Finding] = []
    for path in target.rglob("*"):
        if not path.is_file() or path.suffix.casefold() not in TEXT_EXTENSIONS:
            continue
        relative = path.relative_to(target).as_posix()
        if any(part in IGNORED_DIRECTORIES for part in path.relative_to(target).parts) or any(fnmatch.fnmatch(relative, pattern) for pattern in excludes):
            continue
        if path.stat().st_size > 2_000_000:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(lines, 1):
            if "placeholder-detector: ignore" in line:
                continue
            for rule in RULES:
                if allowed[rule.severity] >= threshold and rule.pattern.search(line):
                    findings.append(Finding(rule.id, rule.severity, rule.message, relative, number, _redact(line), hashlib.sha256(" ".join(line.strip().split()).encode("utf-8")).hexdigest()))
    findings.sort(key=lambda item: (-allowed[item.severity], item.path, item.line, item.rule))
    return tuple(findings)


def _redact(line: str) -> str:
    compact = " ".join(line.strip().split())
    compact = re.sub(r"(?i)(password|secret|token|api[_-]?key)(\s*[:=]\s*)[^\s,;]+", r"\1\2[redacted]", compact)
    return compact[:180] + ("…" if len(compact) > 180 else "")
