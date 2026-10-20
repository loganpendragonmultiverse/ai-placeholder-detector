# Changelog

## 1.2.0 - 2026-10-20

- Report content-free skipped-path evidence and return exit 2 for incomplete scans.
- Keep unmatched baseline findings unverified while any source path was skipped.
- Prune ignored directories, avoid symlinks, bound source reads, and handle report-write failures.
- Redact complete quoted secret assignments, including multiword values and quoted keys.
- Build tested wheel/source distributions from the exact annotated release tag.
- Require explicit --overwrite for existing reports and refuse symlink destinations.
- Exclude report output from repeated scans even without a baseline.

## 1.1.0 - 2026-10-15

- Compare a prior JSON report with occurrence-aware new, unchanged and resolved findings across line shifts.
- Add opt-in --fail-on-new, strict baseline validation and normalized evidence fingerprints while preserving excerpt redaction.
- Accept legacy baselines with their documented redacted-excerpt matching limits.

## 1.0.0 - 2026-07-18

- Added deterministic placeholder and stub detection across common source formats.
- Added safe excerpts, inline ignores, glob exclusions, severity filtering, and JSON output.
- Added an optional CI failure mode.
