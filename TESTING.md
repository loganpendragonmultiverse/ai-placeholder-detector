# Testing

Run `python -m pip install -e . pytest build`, `python -m pytest` and `python -m build`.
Baseline regressions cover shifted duplicate occurrences, changed evidence/path/rule,
legacy report limits, malformed baselines, redacted resolved excerpts, CLI failure
policies and report self-exclusion. Install the built wheel and exercise the CLI too.
