import json
from pathlib import Path

import pytest

from placeholder_detector.cli import main
from placeholder_detector.scanner import scan, scan_report


def test_incomplete_scan_keeps_missing_baseline_unverified(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("# TODO inspect\n", encoding="utf-8")
    baseline = tmp_path / "prior.json"
    assert main([str(tmp_path), "--format", "json", "--output", str(baseline)]) == 0
    source.write_bytes(b"\xff")
    output = tmp_path / "new.json"
    assert main([str(tmp_path), "--baseline", str(baseline), "--format", "json", "--output", str(output), "--fail-on-new"]) == 2
    result = json.loads(output.read_text())
    assert result["complete"] is False
    assert result["skipped"] == [{"path": "app.py", "reason": "invalid-utf8"}]
    assert result["comparison"]["resolved"] == []
    assert len(result["comparison"]["unverified"]) == 1
    assert result["comparison"]["new"] == []


def test_size_bound_and_intentional_exclusions(tmp_path):
    (tmp_path / "big.py").write_bytes(b"x" * 2_000_001)
    (tmp_path / "limit.py").write_bytes(b" " * 1_999_992 + b"# TODO x")
    report = scan_report(tmp_path)
    assert report.skipped == ({"path": "big.py", "reason": "size-limit"},)
    assert [x.path for x in report.findings] == ["limit.py"]
    assert not scan_report(tmp_path, ("big.py",)).skipped


def test_symlinks_never_read_external_content(tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    (external / "secret.py").write_text("# TODO token=private-value\n")
    target = tmp_path / "target"
    target.mkdir()
    try:
        (target / "link.py").symlink_to(external / "secret.py")
        (target / "linked").symlink_to(external, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    report = scan_report(target)
    assert not report.findings
    assert report.skipped == ({"path": "link.py", "reason": "symlink-file"}, {"path": "linked", "reason": "symlink-directory"})
    assert "private-value" not in str(report)
    assert not scan_report(target, ("link.py", "linked")).skipped


def test_unreadable_file_has_content_free_reason(tmp_path, monkeypatch):
    source = tmp_path / "denied.py"
    source.write_text("# TODO sensitive detail\n")
    original = Path.open

    def restricted(path, *args, **kwargs):
        if path == source:
            raise PermissionError("sensitive exception details")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", restricted)
    report = scan_report(tmp_path)
    assert report.skipped == ({"path": "denied.py", "reason": "unreadable-file"},)
    assert "sensitive" not in str(report)


def test_output_is_self_excluded_without_baseline(tmp_path):
    (tmp_path / "app.py").write_text("# TODO real\n")
    output = tmp_path / "report.json"
    args = [str(tmp_path), "--format", "json", "--output", str(output)]
    assert main(args) == main(args + ["--overwrite"]) == 0
    assert json.loads(output.read_text())["count"] == 1


def test_output_failure_returns_two(tmp_path, capsys):
    assert main([str(tmp_path), "--output", str(tmp_path / "absent" / "report.json")]) == 2
    assert "cannot write report" in capsys.readouterr().err


def test_complete_comparison_preserves_resolved(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("# TODO real\n")
    baseline = tmp_path / "prior.json"
    output = tmp_path / "new.json"
    assert main([str(tmp_path), "--format", "json", "--output", str(baseline)]) == 0
    source.write_text("# finished\n")
    assert main([str(tmp_path), "--baseline", str(baseline), "--format", "json", "--output", str(output)]) == 0
    result = json.loads(output.read_text())
    assert result["complete"] and len(result["comparison"]["resolved"]) == 1
    assert "unverified" not in result["comparison"]
    assert scan(tmp_path, ("prior.json", "new.json")) == ()


@pytest.mark.parametrize("line", [
    '# TODO token="private value"',
    "# TODO password='private value'",
    '# TODO {"api_key": "private value"}',
    r'# TODO token="private \"quoted\" value"',
])
def test_quoted_secret_assignment_is_fully_redacted(tmp_path, line):
    (tmp_path / "app.py").write_text(line + "\n")
    excerpt = scan(tmp_path)[0].excerpt
    assert "private" not in excerpt and "value" not in excerpt
    assert "[redacted]" in excerpt


def test_symlink_root_is_rejected(tmp_path):
    target = tmp_path / "source"
    target.mkdir()
    (target / "app.py").write_text("# TODO inspect\n")
    link = tmp_path / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="symlink"):
        scan_report(link)
    assert main([str(link)]) == 2


@pytest.mark.parametrize("line", [
    '# TODO password="private value',
    "# TODO password='private value",
    '# TODO password="private value' + chr(92),
])
def test_unterminated_quoted_secret_is_fully_redacted(tmp_path, line):
    (tmp_path / "app.py").write_text(line + "\n")
    excerpt = scan(tmp_path)[0].excerpt
    assert "private" not in excerpt and "value" not in excerpt
    assert "[redacted]" in excerpt


def test_existing_report_requires_explicit_overwrite(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("previous report")
    args = [str(tmp_path), "--format", "json", "--output", str(output)]
    assert main(args) == 2
    assert output.read_text() == "previous report"
    assert main(args + ["--overwrite"]) == 0
    assert json.loads(output.read_text())["complete"] is True


@pytest.mark.parametrize("overwrite", [False, True])
def test_dangling_output_symlink_is_refused(tmp_path, overwrite):
    target = tmp_path / "absent-target"
    output = tmp_path / "report.json"
    try:
        output.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    args = [str(tmp_path), "--output", str(output)]
    assert main(args + (["--overwrite"] if overwrite else [])) == 2
    assert output.is_symlink() and not target.exists()


def test_report_creation_race_preserves_other_writer(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    original = Path.open

    def race(path, mode="r", *args, **kwargs):
        if path == output and mode == "x":
            with original(path, "w", encoding="utf-8") as handle:
                handle.write("other writer")
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", race)
    assert main([str(tmp_path), "--output", str(output)]) == 2
    assert output.read_text() == "other writer"
