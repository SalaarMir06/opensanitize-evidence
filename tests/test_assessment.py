from copy import deepcopy

import pytest

from ose.assessment import assess_collection


@pytest.fixture
def manifest():
    return {
        "schema_version": "2.0",
        "collection": {
            "collection_id": "assessment-test-001",
            "collector": "OSE test collector",
            "adapter": "test",
            "started_utc": "2026-11-24T10:00:00Z",
            "finished_utc": "2026-11-24T10:01:00Z",
            "status": "COMPLETE",
        },
        "target": {
            "expected_identity": {"serial": "TEST-001"},
            "observations": {"before": None, "after": None},
        },
        "identity": {
            "status": "VERIFIED",
            "checks": {"serial_matches": True},
        },
        "commands": [],
        "artifacts": [],
        "capture": {"status": "COMPLETE"},
        "assessment": {"status": "NOT_ASSESSED"},
        "safety": {
            "read_only_collection": True,
            "destructive_commands_executed": False,
        },
        "extensions": {},
    }


def test_no_operation_is_not_assessed(manifest):
    result = assess_collection(manifest)

    assert result["status"] == "NOT_ASSESSED"
    assert result["findings"][0]["code"] == "NO_SANITIZATION_OPERATION"


def test_read_only_collection_is_not_assessed_even_with_successful_commands(
    manifest,
):
    manifest["commands"] = [{
        "command_id": "cmd-1",
        "name": "diagnostic",
        "argv": ["diagnostic", "--all"],
        "started_utc": "2026-11-24T10:00:00Z",
        "finished_utc": "2026-11-24T10:00:01Z",
        "duration_seconds": 1.0,
        "exit_code": 0,
        "timed_out": False,
        "execution_status": "COMPLETED",
        "artifact_ids": [],
        "extensions": {},
    }]

    result = assess_collection(manifest)

    assert result["status"] == "NOT_ASSESSED"


def test_failed_identity_does_not_prove_sanitization_failure(manifest):
    manifest["identity"]["status"] = "FAILED"

    result = assess_collection(manifest)

    assert result["status"] == "NOT_ASSESSED"


def test_explicit_operation_failure_is_non_conformant(manifest):
    result = assess_collection(
        manifest,
        {"status": "FAILED"},
    )

    assert result["status"] == "NON_CONFORMANT"
    assert result["findings"][0]["code"] == "OPERATION_FAILED"


def test_explicit_verification_failure_is_non_conformant(manifest):
    result = assess_collection(
        manifest,
        {
            "status": "COMPLETED",
            "verification": {"status": "FAILED"},
        },
    )

    assert result["status"] == "NON_CONFORMANT"
    assert result["findings"][0]["code"] == "VERIFICATION_FAILED"


def test_explicit_validation_failure_is_non_conformant(manifest):
    result = assess_collection(
        manifest,
        {
            "status": "COMPLETED",
            "validation": {"status": "FAILED"},
        },
    )

    assert result["status"] == "NON_CONFORMANT"
    assert result["findings"][0]["code"] == "VALIDATION_FAILED"


def test_not_attempted_with_verification_failure_is_non_conformant(
    manifest,
):
    result = assess_collection(
        manifest,
        {
            "status": "NOT_ATTEMPTED",
            "verification": {"status": "FAILED"},
        },
    )

    assert result["status"] == "NON_CONFORMANT"
    assert "VERIFICATION_FAILED" in {
        finding["code"] for finding in result["findings"]
    }


def test_all_explicit_failure_findings_are_preserved(manifest):
    result = assess_collection(
        manifest,
        {
            "status": "FAILED",
            "verification": {"status": "FAILED"},
            "validation": {"status": "FAILED"},
        },
    )

    codes = {finding["code"] for finding in result["findings"]}

    assert result["status"] == "NON_CONFORMANT"
    assert codes == {
        "OPERATION_FAILED",
        "VERIFICATION_FAILED",
        "VALIDATION_FAILED",
    }


def test_not_attempted_without_failures_is_not_assessed(manifest):
    result = assess_collection(
        manifest,
        {"status": "NOT_ATTEMPTED"},
    )

    assert result["status"] == "NOT_ASSESSED"
    assert result["findings"][0]["code"] == "OPERATION_NOT_ATTEMPTED"


def test_incomplete_operation_is_inconclusive(manifest):
    result = assess_collection(
        manifest,
        {"status": "IN_PROGRESS"},
    )

    assert result["status"] == "INCONCLUSIVE"
    assert "OPERATION_NOT_COMPLETED" in {
        finding["code"] for finding in result["findings"]
    }


def test_missing_technique_and_verification_are_inconclusive(manifest):
    result = assess_collection(
        manifest,
        {"status": "COMPLETED"},
    )

    codes = {finding["code"] for finding in result["findings"]}

    assert result["status"] == "INCONCLUSIVE"
    assert "TECHNIQUE_NOT_RECORDED" in codes
    assert "VERIFICATION_NOT_ESTABLISHED" in codes
    assert "VALIDATION_NOT_ESTABLISHED" in codes


def test_complete_evidence_requires_policy_review(manifest):
    result = assess_collection(
        manifest,
        {
            "status": "COMPLETED",
            "technique": "PURGE",
            "verification": {"status": "PASSED"},
            "validation": {"status": "PASSED"},
        },
    )

    assert result["status"] == "UNDER_REVIEW"
    assert result["findings"][0]["code"] == "POLICY_REVIEW_REQUIRED"


def test_engine_does_not_modify_manifest(manifest):
    original = deepcopy(manifest)

    assess_collection(manifest, {"status": "FAILED"})

    assert manifest == original


def test_invalid_manifest_is_rejected(manifest):
    manifest["schema_version"] = "1.0"

    with pytest.raises(ValueError, match="Invalid OSE Evidence"):
        assess_collection(manifest)


@pytest.mark.parametrize(
    "operation",
    [
        {"status": "UNKNOWN_STATUS"},
        {"status": "FAILED", "unexpected": True},
        {"status": "COMPLETED", "technique": ""},
        {"status": "COMPLETED", "verification": {"status": "UNKNOWN_STATUS"}},
        {"status": "COMPLETED", "validation": {"status": "PASSED", "note": "x"}},
        {"status": []},
        {"status": "COMPLETED", "verification": {"status": []}},
        {"status": "COMPLETED", "validation": {"status": {}}},
    ],
)
def test_invalid_operation_evidence_is_rejected(manifest, operation):
    with pytest.raises(ValueError):
        assess_collection(manifest, operation)
