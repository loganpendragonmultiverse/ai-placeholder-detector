# AI Placeholder Detector

AI-assisted projects can look finished while still containing stubbed handlers, fake content, sample domains, or notes that were never resolved. AI Placeholder Detector gives maintainers a fast, local review pass before release.

Despite the name, it does not attempt to determine who wrote the code. It reports concrete unfinished patterns regardless of authorship.

## Detected patterns

- TODO, FIXME, HACK, and XXX markers
- Lorem ipsum and explicit placeholder copy
- Example domains
- Empty or hash-only links
- Explicit “not implemented” runtime paths
- Fake, dummy, mock, or sample-data labels
- Coming-soon copy
- Empty UI handlers
- Fixed empty return stubs

## Install

Python 3.10 or newer is required.

```bash
python -m venv .venv
python -m pip install -e .
```

## Usage

```bash
placeholder-detector .
placeholder-detector . --exclude "examples/*" --exclude "tests/fixtures/*"
placeholder-detector . --format json --output placeholders.json --fail-on-findings
```

For a single intentional match, add `placeholder-detector: ignore` on that line. Prefer a project-level exclusion for generated fixtures rather than scattering ignores throughout source code.

## Privacy

All scanning happens locally. Excerpts are truncated, and obvious secret assignments are redacted before display. The tool never uploads code.

## Limitations

This is a deterministic pattern scanner, not proof that a feature works. A match can be intentional, and an unfinished implementation can avoid every known pattern. Review findings in context.

## Development

```bash
python -m pip install -e . pytest build
python -m pytest
python -m build
```

## Project status

**Version 1.2 adds scan-completeness evidence.** New detection rules should be narrow, explainable, and backed by realistic tests.

Released under the [MIT License](LICENSE). Contributions follow the [organization guidelines](https://github.com/loganpendragonmultiverse/.github/blob/main/CONTRIBUTING.md).

## More open-source projects

This project is part of the [Logan Pendragon Forge open-source collection](https://www.loganpendragonforge.com/open-source/). Browse the catalog for other released tools, source repositories, live demos, and downloads.

## Compare a prior report

Save `placeholder-detector . --format json --output prior.json`, then run
`placeholder-detector . --baseline prior.json --format json --fail-on-new`.
Text and JSON reports separate new, unchanged and resolved occurrences. Matching uses
relative path, rule and a SHA-256 fingerprint of the full whitespace-normalized source
line, ignoring line numbers. Duplicate lines consume separate occurrences. A moved
path, changed rule or changed evidence is new. Inline ignores, exclusions, severity
filters and `--fail-on-findings` still apply; compare with the same scan settings and
root to interpret resolved findings. Resolved means absent from this scan, not fixed.

Version 1.0 reports are accepted using their redacted, truncated excerpts; changes only
beyond truncation or inside redacted text cannot be distinguished in those baselines.
Version 1.1 retains redacted excerpts and stores full-line fingerprints, not raw lines.
Fingerprints are not encryption and can reveal equality or allow guessing low-entropy
lines. Baseline and output files inside the target are excluded during comparison.
Invalid baselines return exit 2. `--fail-on-new` requires a baseline and returns exit 1
only for new findings (or any findings if combined with `--fail-on-findings`).

## Scan completeness

JSON reports include `complete` and a content-free `skipped` list. Unreadable
source files/directories, invalid UTF-8, files larger than 2,000,000 bytes and
symlinks make a scan incomplete; the CLI writes the evidence and returns exit 2.
Symlinks are never followed; a selected root containing symlink components is rejected. Ignored directories, unsupported extensions and
explicit exclusions are intentional scope choices, not incomplete-read warnings.
The scanner prunes ignored directories rather than traversing their contents.

When any path is skipped, unmatched baseline findings move to `unverified`, not
`resolved`. Matching/new occurrences are still reported, but `--fail-on-new` cannot
turn an incomplete scan into success. Resolve or explicitly exclude skipped paths
before using the scan as a release check. Scan only a stable tree: concurrent file
changes are not an atomic snapshot. Output/baseline files inside the target are
excluded automatically. Output failures return exit 2.

Python callers can use `scan_report()` for both findings and skipped paths; legacy
`scan()` still returns findings only and does not certify complete inspection.
