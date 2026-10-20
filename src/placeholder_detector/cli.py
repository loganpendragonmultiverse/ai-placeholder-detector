from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan_report
from .baseline import compare, load_baseline


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="placeholder-detector", description="Find unfinished placeholders in a source tree.")
    result.add_argument("target", nargs="?", default=".")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path)
    result.add_argument("--overwrite", action="store_true", help="replace an existing regular report file")
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
        if args.baseline or args.output:
            for report_path in (args.baseline, args.output):
                if report_path:
                    try:
                        excludes.append(report_path.resolve().relative_to(Path(args.target).resolve()).as_posix())
                    except ValueError:
                        pass
        scanned = scan_report(Path(args.target), tuple(excludes), args.minimum)
        findings = scanned.findings
        comparison = compare(findings, baseline) if baseline is not None else None
        if comparison is not None and scanned.skipped:
            comparison["unverified"] = comparison["resolved"]
            comparison["resolved"] = []
    except (OSError, ValueError) as exc:
        print(f"placeholder-detector: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        data = {"count": len(findings), "findings": [item.to_dict() for item in findings], "complete": not scanned.skipped, "skipped": list(scanned.skipped)}
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
        if scanned.skipped:
            lines.append("Scan incomplete; skipped paths:")
            lines.extend(f"  {item['path']} [{item['reason']}]" for item in scanned.skipped)
        report = "\n".join(lines)
    try:
        if args.output:
            if args.output.is_symlink():
                raise ValueError("output must not be a symlink")
            if args.output.exists() and not args.overwrite:
                raise ValueError("output exists; use --overwrite to replace a regular report")
            with args.output.open("w" if args.overwrite else "x", encoding="utf-8") as handle:
                handle.write(report + "\n")
            print(f"Wrote {args.format} report to {args.output}")
        else:
            print(report)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"placeholder-detector: cannot write report: {exc}", file=sys.stderr)
        return 2
    if scanned.skipped:
        return 2
    return 1 if (args.fail_on_findings and findings) or (args.fail_on_new and comparison and comparison["new"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
