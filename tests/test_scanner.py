from pathlib import Path

from placeholder_detector.scanner import scan


def test_detects_multiple_placeholder_types(tmp_path: Path) -> None:
    (tmp_path / "app.tsx").write_text('const a = "Lorem ipsum";\n<a href="#">Open</a>\n// TODO finish export\n', encoding="utf-8")
    findings = scan(tmp_path)
    assert {item.rule for item in findings} == {"placeholder-copy", "empty-link", "unfinished-marker"}


def test_excludes_generated_paths(tmp_path: Path) -> None:
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "fixture.js").write_text("// TODO generated\n", encoding="utf-8")
    assert scan(tmp_path, ("generated/*",)) == ()


def test_inline_ignore_is_narrow(tmp_path: Path) -> None:
    (tmp_path / "rules.py").write_text("# TODO documented rule  # placeholder-detector: ignore\n# FIXME real\n", encoding="utf-8")
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].line == 2


def test_excerpt_redacts_obvious_secret_assignment(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text("// TODO token=do-not-print-this\n", encoding="utf-8")
    assert "do-not-print-this" not in scan(tmp_path)[0].excerpt
