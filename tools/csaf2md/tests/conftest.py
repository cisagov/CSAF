from pathlib import Path
import sys
from typing import List, Tuple

import pytest

CSAF2MD_DIR = Path(__file__).resolve().parents[1]
RESOURCES_DIR = CSAF2MD_DIR / "tests" / "resources"
INPUT_DIR = RESOURCES_DIR / "input"
EXPECTED_DIR = RESOURCES_DIR / "expected"

if str(CSAF2MD_DIR) not in sys.path:
    sys.path.insert(0, str(CSAF2MD_DIR))


@pytest.fixture
def resources_dir() -> Path:
    return RESOURCES_DIR


def _case_label(input_path: Path, expected_path: Path) -> str:
    # Optional convention:
    # - file naming: "<label>__anything.json" -> label is used in test IDs/summary
    # - expected top comment: "<!-- case: your-label -->" overrides file label
    label = input_path.stem.split("__", 1)[0]
    first_line = expected_path.read_text(encoding="utf-8").splitlines()[:1]
    if first_line and first_line[0].lower().startswith("<!-- case:") and first_line[0].endswith("-->"):
        label = first_line[0][10:-3].strip() or label
    return label


def snapshot_cases() -> List[Tuple[str, Path, Path]]:
    cases: List[Tuple[str, Path, Path]] = []
    for input_path in sorted(INPUT_DIR.glob("*.json")):
        expected_path = EXPECTED_DIR / f"{input_path.stem}.md"
        label = _case_label(input_path, expected_path) if expected_path.exists() else input_path.stem
        cases.append((label, input_path, expected_path))
    return cases


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    cases = snapshot_cases()
    total_cases = len(cases)
    passed = 0
    failed = 0
    for report in terminalreporter.stats.get("passed", []):
        if "test_process_json_snapshot_resources" in report.nodeid:
            passed += 1
    for report in terminalreporter.stats.get("failed", []):
        if "test_process_json_snapshot_resources" in report.nodeid:
            failed += 1

    terminalreporter.write_sep("-", "csaf2md integration test summary")
    terminalreporter.write_line(f"snapshot cases: {total_cases}")
    terminalreporter.write_line(f"snapshot pass:  {passed}")
    terminalreporter.write_line(f"snapshot fail:  {failed}")
