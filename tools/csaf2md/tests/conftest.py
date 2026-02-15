from pathlib import Path
import sys
from typing import List, Tuple

import pytest

CSAF2MD_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
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


def smoke_cases() -> List[Tuple[str, Path]]:
    # Cover all advisory files under year folders:
    # csaf_files/<IT|OT>/white/<YYYY>/*.json
    cases: List[Tuple[str, Path]] = []
    for family in ("IT", "OT"):
        base = REPO_ROOT / "csaf_files" / family / "white"
        for input_path in sorted(base.glob("[0-9][0-9][0-9][0-9]/*.json")):
            label = f"{family.lower()}_{input_path.stem}"
            cases.append((label, input_path))
    return cases


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    snap = snapshot_cases()
    smoke = smoke_cases()
    snapshot_passed = 0
    snapshot_failed = 0
    smoke_converted = 0
    smoke_expected_reject = 0
    smoke_unexpected_failure = 0
    smoke_report_count = 0

    def _smoke_outcome(report):
        for key, value in getattr(report, "user_properties", []):
            if key == "smoke_outcome":
                return value
        return None

    for report in terminalreporter.stats.get("passed", []):
        if "test_process_json_snapshot_resources" in report.nodeid:
            snapshot_passed += 1
    for report in terminalreporter.stats.get("failed", []):
        if "test_process_json_snapshot_resources" in report.nodeid:
            snapshot_failed += 1

    smoke_reports = []
    smoke_reports.extend(terminalreporter.stats.get("passed", []))
    smoke_reports.extend(terminalreporter.stats.get("failed", []))
    smoke_reports.extend(terminalreporter.stats.get("skipped", []))

    for report in smoke_reports:
        if getattr(report, "when", "call") != "call":
            continue
        if "test_process_json_smoke" not in report.nodeid:
            continue
        smoke_report_count += 1
        outcome = _smoke_outcome(report)
        if outcome == "converted":
            smoke_converted += 1
        elif outcome == "expected_reject":
            smoke_expected_reject += 1
        elif outcome == "unexpected_failure":
            smoke_unexpected_failure += 1

    terminalreporter.write_sep("-", "csaf2md integration test summary")
    terminalreporter.write_line(f"snapshot cases: {len(snap)}")
    terminalreporter.write_line(f"snapshot pass:  {snapshot_passed}")
    terminalreporter.write_line(f"snapshot fail:  {snapshot_failed}")
    terminalreporter.write_line(f"smoke cases:    {len(smoke)}")
    terminalreporter.write_line(f"smoke converted:          {smoke_converted}")
    terminalreporter.write_line(f"smoke expected reject:    {smoke_expected_reject}")
    terminalreporter.write_line(f"smoke unexpected failure: {smoke_unexpected_failure}")
    terminalreporter.write_line(f"smoke reports seen:       {smoke_report_count}")
