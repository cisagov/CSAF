import json
from pathlib import Path

import pytest
from csaf2md import processJson
from lib.requirements import meets_minimum_requirements
from conftest import EXPECTED_DIR, INPUT_DIR, snapshot_cases


def test_snapshot_resources_are_paired():
    inputs = {p.stem for p in INPUT_DIR.glob("*.json")}
    expected = {p.stem for p in EXPECTED_DIR.glob("*.md")}
    assert inputs == expected, (
        f"Input/expected mismatch. only_input={sorted(inputs - expected)}, "
        f"only_expected={sorted(expected - inputs)}"
    )


@pytest.mark.parametrize(
    "label,input_path,expected_path",
    snapshot_cases(),
    ids=[case[0] for case in snapshot_cases()],
)
def test_meets_minimum_requirements_for_snapshot_inputs(label: str, input_path: Path, expected_path: Path):
    del label, expected_path
    data = json.loads(input_path.read_text(encoding="utf-8"))
    valid, errors = meets_minimum_requirements(data)
    assert valid is True, errors
    assert errors == []


@pytest.mark.parametrize(
    "label,input_path,expected_path",
    snapshot_cases(),
    ids=[case[0] for case in snapshot_cases()],
)
def test_process_json_snapshot_resources(label: str, input_path: Path, expected_path: Path, tmp_path):
    del label
    output_file = tmp_path / f"{input_path.stem}.md"
    processJson(str(input_path), str(output_file))
    assert output_file.exists()
    actual = output_file.read_text(encoding="utf-8").replace("\r\n", "\n")
    expected = expected_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert actual == expected
