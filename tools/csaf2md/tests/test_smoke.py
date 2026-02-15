import json
from pathlib import Path

import pytest
import csaf2md as csaf2md_mod
from conftest import smoke_cases

SMOKE_CASES = smoke_cases()
KNOWN_REJECTION_MARKERS = (
    "does not meet minimum data requirements",
    "has discouraged or prohibited CWEs",
    "is not scored for Vulnerability",
    'CVSS "scores" lists products',
)
CRASH_MARKERS = (
    "Traceback",
    "ERROR:",
)


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


@pytest.mark.parametrize(
    "label,input_path",
    SMOKE_CASES,
    ids=[case[0] for case in SMOKE_CASES],
)
def test_process_json_smoke(label: str, input_path: Path, tmp_path, capsys, record_property):
    del label
    assert input_path.exists(), f"Smoke input file not found: {input_path}"

    with input_path.open("r", encoding="utf-8") as infile:
        advisory = json.load(infile)
    advisory_id = advisory["document"]["tracking"]["id"].upper()

    # Keep smoke side effects out of repo paths.
    csaf2md_mod.workingdir = str(tmp_path)
    output_file = tmp_path / f"{input_path.stem}.md"
    csaf2md_mod.processJson(str(input_path), str(output_file))

    # Collect tool logs to classify handled reject vs unexpected failure.
    captured = capsys.readouterr()
    logs = f"{captured.out}\n{captured.err}"

    if output_file.exists():
        output_text = output_file.read_text(encoding="utf-8")
        assert f"## {advisory_id}" in output_text
        assert "## 1. EXECUTIVE SUMMARY" in output_text
        record_property("smoke_outcome", "converted")
        return

    has_known_reject = _contains_any(logs, KNOWN_REJECTION_MARKERS)
    has_crash = _contains_any(logs, CRASH_MARKERS)

    if has_known_reject and not has_crash:
        record_property("smoke_outcome", "expected_reject")
        return

    record_property("smoke_outcome", "unexpected_failure")
    excerpt = logs[-1200:] if logs else "<no converter output captured>"
    pytest.fail(
        "Smoke case had no markdown output and was not a recognized safe reject.\n"
        f"advisory={input_path}\n"
        f"known_reject={has_known_reject} crash_marker={has_crash}\n"
        f"log_excerpt:\n{excerpt}"
    )
