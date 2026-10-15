"""Occurrence-aware comparison of locally supplied scanner reports."""
from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from pathlib import Path

from .scanner import Finding, _redact


def load_baseline(path: Path) -> tuple[Finding, ...]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid baseline JSON") from exc
    if (not isinstance(data, dict) or not isinstance(data.get("findings"), list)
            or type(data.get("count")) is not int or data["count"] != len(data["findings"])):
        raise ValueError("Baseline requires count and a matching findings array")
    results = []
    for item in data["findings"]:
        required = {"rule", "severity", "message", "path", "line", "excerpt"}
        if (not isinstance(item, dict) or not required <= item.keys()
                or item.keys() - required - {"evidence_sha256"}
                or any(not isinstance(item[key], str) for key in required - {"line"})
                or not item["rule"] or not item["path"]
                or item["severity"] not in {"info", "warning", "error"}
                or type(item["line"]) is not int or item["line"] < 1
                or ("evidence_sha256" in item and (not isinstance(item["evidence_sha256"], str) or not re.fullmatch("[0-9a-f]{64}", item["evidence_sha256"])))):
            raise ValueError("Invalid baseline finding")
        results.append(Finding(**{**item, "excerpt": _redact(item["excerpt"])}))
    return tuple(results)


def compare(findings: tuple[Finding, ...], baseline: tuple[Finding, ...]) -> dict[str, list[dict[str, object]]]:
    # A queue consumes one old occurrence per current occurrence, retaining duplicates.
    old = defaultdict(deque)
    for index, finding in enumerate(baseline):
        evidence = finding.evidence_sha256 or finding.excerpt
        old[(finding.path, finding.rule, evidence)].append(index)
    matched = set()
    result: dict[str, list[dict[str, object]]] = {"new": [], "unchanged": [], "resolved": []}
    for finding in findings:
        key = (finding.path, finding.rule, finding.evidence_sha256 or finding.excerpt)
        # Legacy reports contain only the redacted, truncated excerpt.
        legacy = (finding.path, finding.rule, finding.excerpt)
        queue = old[key] if old[key] else old[legacy]
        if queue:
            matched.add(queue.popleft())
            result["unchanged"].append(finding.to_dict())
        else:
            result["new"].append(finding.to_dict())
    result["resolved"] = [finding.to_dict() for i, finding in enumerate(baseline) if i not in matched]
    return result
