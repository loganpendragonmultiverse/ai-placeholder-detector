# Testing

Run `python -m pip install -e . pytest build`, `python -m pytest` and `python -m build`.
Baseline regressions cover shifted duplicate occurrences, changed evidence/path/rule,
legacy report limits, malformed baselines, redacted resolved excerpts, CLI failure
policies and report self-exclusion. Install the built wheel and exercise the CLI too.

Completeness regressions cover bounded reads at 2,000,000 bytes, invalid UTF-8,
read failures, outside-root symlinks, explicit exclusions, output self-exclusion,
output failure, and unverified versus resolved baseline evidence. Run the complete
test suite from both an installed wheel and an installed source distribution.

Redaction fixtures include multiword quoted assignments and JSON-style quoted keys.

Output regressions cover existing regular reports, explicit overwrite, dangling
symlinks and a competing writer creating a regular file before open('x').
