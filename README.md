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

**Feature complete for v1.0.** New detection rules should be narrow, explainable, and backed by realistic tests.

Released under the [MIT License](LICENSE). Contributions follow the [organization guidelines](https://github.com/loganpendragonmultiverse/.github/blob/main/CONTRIBUTING.md).
