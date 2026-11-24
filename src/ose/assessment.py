"""Deterministic assessment of structured sanitization evidence.

This module does not execute device operations, inspect raw command output,
or infer sanitization outcomes from command names or exit codes.

The caller is responsible for verifying package integrity before relying
on an assessment result.
"""

from copy import deepcopy

from ose.evidence_schema import assert_valid_manifest


ASSESSMENT_ENGINE_VERSION = "1.0"

OPERATION_STATUSES = {
    "NOT_ATTEMPTED",
    "IN_PROGRESS",
    "COMPLETED",
    "FAILED",
    "UNKNOWN",
}

VERIFICATION_STATUSES = {
    "NOT_PERFORMED",
    "PASSED",
    "FAILED",
    "INCOMPLETE",
    "UNKNOWN",
}

VALIDATION_STATUSES = {
    "NOT_PERFORMED",
    "PASSED",
    "FAILED",
    "PENDING",
    "UNKNOWN",
}


def _validate_operation(operation):
    """Validate the normalized sanitization-operation evidence."""

    if not isinstance(operation, dict):
        raise ValueError("operation must be a JSON object")

    allowed_fields = {
        "status",
        "technique",
        "verification",
        "validation",
    }

    unknown_fields = set(operation) - allowed_fields

    if unknown_fields:
        raise ValueError(
            f"Unknown operation fields: {sorted(unknown_fields)}"
        )

    status = operation.get("status")

    if not isinstance(status, str) or status not in OPERATION_STATUSES:
        raise ValueError("operation.status is invalid")

    technique = operation.get("technique")

    if technique is not None and (
        not isinstance(technique, str) or not technique.strip()
    ):
        raise ValueError(
            "operation.technique must be a non-empty string or null"
        )

    for field, allowed_statuses in (
        ("verification", VERIFICATION_STATUSES),
        ("validation", VALIDATION_STATUSES),
    ):
        default_value = {"status": "NOT_PERFORMED"}
        value = operation.get(field, default_value)

        if not isinstance(value, dict):
            raise ValueError(f"operation.{field} must be an object")

        if set(value) != {"status"}:
            raise ValueError(
                f"operation.{field} must contain only status"
            )

        field_status = value["status"]

        if (
            not isinstance(field_status, str)
            or field_status not in allowed_statuses
        ):
            raise ValueError(f"operation.{field}.status is invalid")

    return {
        "status": status,
        "technique": technique,
        "verification": operation.get(
            "verification",
            {"status": "NOT_PERFORMED"},
        )["status"],
        "validation": operation.get(
            "validation",
            {"status": "NOT_PERFORMED"},
        )["status"],
    }


def assess_collection(manifest, operation=None):
    """Return a deterministic assessment without modifying the manifest.

    `manifest` must be a valid OSE Evidence Schema 2.0 manifest.

    `operation` is separate, normalized sanitization evidence. It must
    not be inferred from the collector's diagnostic commands.

    This initial engine deliberately does not issue CONFORMANT. That
    requires an approved, technique-specific assessment policy.
    """

    assert_valid_manifest(manifest)

    if operation is None:
        return {
            "engine_version": ASSESSMENT_ENGINE_VERSION,
            "status": "NOT_ASSESSED",
            "findings": [
                {
                    "code": "NO_SANITIZATION_OPERATION",
                    "severity": "INFO",
                    "message": (
                        "No structured sanitization operation "
                        "was supplied."
                    ),
                }
            ],
        }

    evidence = _validate_operation(operation)
    findings = []

    if evidence["status"] == "FAILED":
        findings.append({
            "code": "OPERATION_FAILED",
            "severity": "ERROR",
            "message": "The sanitization operation is recorded as failed.",
        })

    if evidence["verification"] == "FAILED":
        findings.append({
            "code": "VERIFICATION_FAILED",
            "severity": "ERROR",
            "message": "The recorded sanitization verification failed.",
        })

    if evidence["validation"] == "FAILED":
        findings.append({
            "code": "VALIDATION_FAILED",
            "severity": "ERROR",
            "message": "The recorded sanitization validation failed.",
        })

    if findings:
        status = "NON_CONFORMANT"

    elif evidence["status"] == "NOT_ATTEMPTED":
        status = "NOT_ASSESSED"
        findings.append({
            "code": "OPERATION_NOT_ATTEMPTED",
            "severity": "INFO",
            "message": "The sanitization operation was not attempted.",
        })

    else:
        status = "INCONCLUSIVE"

        if evidence["status"] != "COMPLETED":
            findings.append({
                "code": "OPERATION_NOT_COMPLETED",
                "severity": "WARNING",
                "message": (
                    "The sanitization operation is not recorded "
                    "as completed."
                ),
            })

        if not evidence["technique"]:
            findings.append({
                "code": "TECHNIQUE_NOT_RECORDED",
                "severity": "WARNING",
                "message": "The sanitization technique is not recorded.",
            })

        if evidence["verification"] != "PASSED":
            findings.append({
                "code": "VERIFICATION_NOT_ESTABLISHED",
                "severity": "WARNING",
                "message": (
                    "Successful technique-specific verification "
                    "has not been established."
                ),
            })

        if evidence["validation"] != "PASSED":
            findings.append({
                "code": "VALIDATION_NOT_ESTABLISHED",
                "severity": "WARNING",
                "message": (
                    "Successful sanitization validation "
                    "has not been established."
                ),
            })

        if manifest["identity"]["status"] != "VERIFIED":
            findings.append({
                "code": "TARGET_IDENTITY_NOT_VERIFIED",
                "severity": "WARNING",
                "message": (
                    "The target device identity is not verified."
                ),
            })

        if manifest["collection"]["status"] != "COMPLETE":
            findings.append({
                "code": "COLLECTION_INCOMPLETE",
                "severity": "WARNING",
                "message": "The evidence collection is incomplete.",
            })

        if manifest["capture"]["status"] != "COMPLETE":
            findings.append({
                "code": "CAPTURE_INCOMPLETE",
                "severity": "WARNING",
                "message": "The evidence capture is incomplete.",
            })

        if not findings:
            status = "UNDER_REVIEW"
            findings.append({
                "code": "POLICY_REVIEW_REQUIRED",
                "severity": "INFO",
                "message": (
                    "The supplied operation evidence is complete, "
                    "but an approved assessment policy and audit "
                    "review are required before a conformance "
                    "conclusion can be issued."
                ),
            })

    return {
        "engine_version": ASSESSMENT_ENGINE_VERSION,
        "status": status,
        "findings": findings,
        "operation": deepcopy(evidence),
    }
