from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan
from .baseline import compare, load_baseline


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="placeholder-detector", description="Find unfinished placeholders in a source tree.")
    result.add_argument("target", nargs="?", default=".")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path)
    result.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude a repository-relative glob; repeat as needed")
    result.add_argument("--minimum", choices=("info", "warning", "error"), default="warning")
    result.add_argument("--fail-on-findings", action="store_true", help="exit 1 when findings remain")
    result.add_argument("--baseline", type=Path, help="compare a prior JSON report")
    result.add_argument("--fail-on-new", action="store_true", help="with --baseline, exit 1 for new findings")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.fail_on_new and not args.baseline:
        parser().error("--fail-on-new requires --baseline")
    try:
        baseline = load_baseline(args.baseline) if args.baseline else None
        excludes = list(args.exclude)
        if args.baseline:
            for report_path in (args.baseline, args.output):
                if report_path:
                    try:
                        excludes.append(report_path.resolve().relative_to(Path(args.target).resolve()).as_posix())
                    except ValueError:
                        pass
        findings = scan(Path(args.target), tuple(excludes), args.minimum)
        comparison = compare(findings, baseline) if baseline is not None else None
    except (OSError, ValueError) as exc:
        print(f"placeholder-detector: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        data = {"count": len(findings), "findings": [item.to_dict() for item in findings]}
        if comparison is not None:
            data["comparison"] = comparison
        report = json.dumps(data, indent=2, ensure_ascii=False)
    else:
        lines = [f"Placeholder findings: {len(findings)}", ""]
        for item in findings:
            lines.extend((f"{item.severity.upper():7} {item.path}:{item.line} [{item.rule}]", f"        {item.message}: {item.excerpt}"))
        if comparison is not None:
            for label, items in comparison.items():
                lines.append(f"{label.capitalize()}: {len(items)}")
                for item in items:
                    lines.append(f"  {item['path']}:{item['line']} [{item['rule']}] {item['excerpt']}")
        report = "\n".join(lines)
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
        print(f"Wrote {args.format} report to {args.output}")
    else:
        print(report)
    return 1 if (args.fail_on_findings and findings) or (args.fail_on_new and comparison and comparison["new"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
