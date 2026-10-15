import json
from dataclasses import replace
from pathlib import Path

import pytest

from placeholder_detector.baseline import compare, load_baseline
from placeholder_detector.cli import main
from placeholder_detector.scanner import scan


def test_shifted_duplicates_and_changed_evidence(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("# TODO one\n# TODO one\n# TODO two\n")
    old = scan(tmp_path)
    source.write_text("\n\n# TODO one\n# TODO changed\n")
    result = compare(scan(tmp_path), old)
    assert len(result["new"]) == 1
    assert len(result["unchanged"]) == 1
    assert result["unchanged"][0]["line"] == 3
    assert len(result["resolved"]) == 2
    for changed in [replace(old[0], path="other.py"), replace(old[0], rule="other")]:
        assert len(compare((changed,), (old[0],))["new"]) == 1
    assert len(compare(old, old[:1])["new"]) == 2


def test_full_evidence_changes_even_beyond_truncation_and_redaction(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("# TODO " + "x" * 200 + "old\n# TODO token=secret-one\n")
    old = scan(tmp_path)
    source.write_text("# TODO " + "x" * 200 + "new\n# TODO token=secret-two\n")
    new = scan(tmp_path)
    assert [f.excerpt for f in old] == [f.excerpt for f in new]
    assert len(compare(new, old)["new"]) == 2
    assert "secret-one" not in json.dumps(compare(new, old))


def test_legacy_baseline_and_resolved_redaction(tmp_path):
    path = tmp_path / "old.json"
    item = {"rule": "unfinished-marker", "severity": "warning", "message": "Marker", "path": "app.py", "line": 1, "excerpt": "# TODO token=private"}
    path.write_text(json.dumps({"count": 1, "findings": [item]}))
    old = load_baseline(path)
    assert "private" not in old[0].excerpt
    result = compare((replace(old[0], line=8, evidence_sha256="a" * 64),), old)
    assert len(result["unchanged"]) == 1
    assert "private" not in json.dumps(compare((), old))


@pytest.mark.parametrize("data", [None, [], {}, {"count": True, "findings": []}, {"count": 1, "findings": []}, {"count": 1, "findings": [None]}, *[
    {"count": 1, "findings": [{"rule": "x", "severity": "warning", "message": "m", "path": "a", "line": 1, "excerpt": "e", **change}]}
    for change in [{"line": True}, {"line": 0}, {"severity": "bad"}, {"path": ""}, {"rule": ""}, {"evidence_sha256": 7}, {"evidence_sha256": "bad"}, {"excerpt": []}, {"extra": 1}]
]])
def test_invalid_baselines(tmp_path, data):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError): load_baseline(path)


def test_cli_policies_filters_and_self_exclusion(tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text("# TODO real\n# TODO intentional placeholder-detector: ignore\n")
    baseline = tmp_path / "baseline.json"
    output = tmp_path / "current.json"
    assert main([str(tmp_path), "--format", "json", "--output", str(baseline)]) == 0
    args = [str(tmp_path), "--baseline", str(baseline), "--fail-on-new", "--exclude", "current.json"]
    assert main(args + ["--format", "json", "--output", str(output)]) == 0
    assert json.loads(output.read_text())["comparison"]["new"] == []
    assert main(args + ["--fail-on-findings"]) == 1
    source.write_text("# TODO real\n# FIXME added\n")
    assert main(args) == 1
    assert main(args + ["--exclude", "app.py"]) == 0
    assert main(args + ["--minimum", "error"]) == 0
    baseline.write_text("bad json")
    assert main(args) == 2
    assert "Invalid baseline" in capsys.readouterr().err
    with pytest.raises(SystemExit) as error: main([str(tmp_path), "--fail-on-new"])
    assert error.value.code == 2
