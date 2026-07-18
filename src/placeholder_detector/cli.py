from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="placeholder-detector", description="Find unfinished placeholders in a source tree.")
    result.add_argument("target", nargs="?", default=".")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path)
    result.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude a repository-relative glob; repeat as needed")
    result.add_argument("--minimum", choices=("info", "warning", "error"), default="warning")
    result.add_argument("--fail-on-findings", action="store_true", help="exit 1 when findings remain")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        findings = scan(Path(args.target), tuple(args.exclude), args.minimum)
    except (OSError, ValueError) as exc:
        print(f"placeholder-detector: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        report = json.dumps({"count": len(findings), "findings": [item.to_dict() for item in findings]}, indent=2, ensure_ascii=False)
    else:
        lines = [f"Placeholder findings: {len(findings)}", ""]
        for item in findings:
            lines.extend((f"{item.severity.upper():7} {item.path}:{item.line} [{item.rule}]", f"        {item.message}: {item.excerpt}"))
        report = "\n".join(lines)
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
        print(f"Wrote {args.format} report to {args.output}")
    else:
        print(report)
    return 1 if args.fail_on_findings and findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
