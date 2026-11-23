from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from ose.evidence_schema import (
    assert_valid_manifest,
    validate_manifest,
)


@pytest.fixture
def valid_manifest():
    return {
        "schema_version": "2.0",
        "collection": {
            "collection_id": "test-collection-001",
            "collector": "OSE",
            "adapter": "openSeaChest",
            "started_utc": "2026-11-15T08:31:14+00:00",
            "finished_utc": "2026-11-15T08:31:15+00:00",
            "status": "COMPLETE",
        },
        "target": {
            "expected_identity": {
                "serial": "TEST-SERIAL-0001"
            },
            "observations": {
                "before": {
                    "path": "/dev/sda",
                    "serial": "TEST-SERIAL-0001",
                },
                "after": {
                    "path": "/dev/sda",
                    "serial": "TEST-SERIAL-0001",
                },
            },
        },
        "identity": {
            "status": "VERIFIED",
            "checks": {
                "serial_matches": True
            },
        },
        "commands": [
            {
                "command_id": "cmd-version",
                "name": "version",
                "argv": ["/usr/bin/tool", "--version"],
                "started_utc": "2026-11-15T08:31:14+00:00",
                "finished_utc": "2026-11-15T08:31:14+00:00",
                "duration_seconds": 0.01,
                "exit_code": 0,
                "timed_out": False,
                "execution_status": "COMPLETED",
                "artifact_ids": [
                    "cmd-version-stdout",
                    "cmd-version-stderr",
                ],
                "extensions": {},
            }
        ],
        "artifacts": [
            {
                "artifact_id": "cmd-version-stdout",
                "role": "stdout",
                "path": "version.stdout.bin",
                "media_type": "application/octet-stream",
                "size_bytes": 12,
                "hash": {
                    "algorithm": "sha256",
                    "value": "a" * 64,
                },
            },
            {
                "artifact_id": "cmd-version-stderr",
                "role": "stderr",
                "path": "version.stderr.bin",
                "media_type": "application/octet-stream",
                "size_bytes": 0,
                "hash": {
                    "algorithm": "sha256",
                    "value": "b" * 64,
                },
            },
        ],
        "capture": {
            "status": "COMPLETE"
        },
        "assessment": {
            "status": "NOT_ASSESSED"
        },
        "safety": {
            "read_only_collection": True,
            "destructive_commands_executed": False,
        },
        "extensions": {
            "openseachest": {
                "executable": "/usr/local/bin/openSeaChest_Info"
            }
        },
    }


def test_valid_manifest_passes(valid_manifest):
    assert validate_manifest(valid_manifest) == []
    assert_valid_manifest(valid_manifest)


def test_rejects_wrong_schema_version(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["schema_version"] = "1.0"

    assert any(
        "schema_version" in error
        for error in validate_manifest(manifest)
    )


def test_rejects_unsafe_artifact_path(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["path"] = "../outside.bin"

    assert any(
        "safe relative path" in error
        for error in validate_manifest(manifest)
    )


def test_rejects_absolute_artifact_path(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["path"] = "/tmp/evidence.bin"

    assert any(
        "safe relative path" in error
        for error in validate_manifest(manifest)
    )


def test_rejects_invalid_sha256(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["hash"]["value"] = "not-a-hash"

    assert any(
        "SHA-256" in error
        for error in validate_manifest(manifest)
    )


def test_rejects_unknown_artifact_reference(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["commands"][0]["artifact_ids"].append("missing-artifact")

    assert any(
        "unknown artifact_id" in error
        for error in validate_manifest(manifest)
    )


def test_rejects_duplicate_command_ids(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["commands"].append(
        deepcopy(manifest["commands"][0])
    )

    assert any(
        "duplicate command_id" in error
        for error in validate_manifest(manifest)
    )


def test_rejects_timed_out_command_with_exit_code(valid_manifest):
    manifest = deepcopy(valid_manifest)
    command = manifest["commands"][0]
    command["timed_out"] = True
    command["execution_status"] = "TIMED_OUT"

    assert any(
        "exit_code must be null" in error
        for error in validate_manifest(manifest)
    )


def test_rejects_missing_timezone(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["collection"]["started_utc"] = "2026-11-15T08:31:14"

    assert any(
        "timezone" in error
        for error in validate_manifest(manifest)
    )


def test_rejects_non_object_manifest():
    assert validate_manifest([]) == [
        "manifest must be a JSON object"
    ]


def test_assert_valid_manifest_raises(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["capture"]["status"] = "UNKNOWN"

    with pytest.raises(ValueError, match="Invalid OSE Evidence"):
        assert_valid_manifest(manifest)


def test_rejects_collection_finish_before_start(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["collection"]["started_utc"] = "2026-11-15T09:00:00+00:00"
    manifest["collection"]["finished_utc"] = "2026-11-15T08:00:00+00:00"

    errors = validate_manifest(manifest)

    assert any("collection.started_utc" in error for error in errors)


def test_rejects_command_finish_before_start(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["commands"][0]["started_utc"] = "2026-11-15T09:00:00+00:00"
    manifest["commands"][0]["finished_utc"] = "2026-11-15T08:00:00+00:00"

    errors = validate_manifest(manifest)

    assert any("commands[0].started_utc" in error for error in errors)


def test_rejects_duplicate_artifact_paths(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][1]["path"] = manifest["artifacts"][0]["path"]

    errors = validate_manifest(manifest)

    assert any("duplicate artifact path" in error for error in errors)


def test_allows_complete_capture_with_identity_not_checked(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["capture"]["status"] = "COMPLETE"
    manifest["identity"]["status"] = "NOT_CHECKED"
    manifest["assessment"]["status"] = "NOT_ASSESSED"

    assert validate_manifest(manifest) == []


def test_capture_completeness_does_not_imply_sanitization_conformance(
    valid_manifest,
):
    manifest = deepcopy(valid_manifest)
    manifest["capture"]["status"] = "COMPLETE"
    manifest["assessment"]["status"] = "NOT_ASSESSED"

    assert validate_manifest(manifest) == []


@pytest.fixture
def json_schema_validator():
    schema_path = (
        Path(__file__).parents[1]
        / "src"
        / "ose"
        / "schemas"
        / "evidence-2.0.schema.json"
    )

    with schema_path.open(encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    Draft202012Validator.check_schema(schema)

    return Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )


def test_json_schema_accepts_valid_manifest(
    valid_manifest,
    json_schema_validator,
):
    errors = list(json_schema_validator.iter_errors(valid_manifest))

    assert errors == []


def test_json_schema_rejects_wrong_version(
    valid_manifest,
    json_schema_validator,
):
    manifest = deepcopy(valid_manifest)
    manifest["schema_version"] = "1.0"

    errors = list(json_schema_validator.iter_errors(manifest))

    assert errors


def test_json_schema_rejects_unsafe_artifact_path(
    valid_manifest,
    json_schema_validator,
):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["path"] = "../outside.bin"

    errors = list(json_schema_validator.iter_errors(manifest))

    assert errors


def test_json_schema_rejects_del_in_path(
    valid_manifest,
    json_schema_validator,
):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["path"] = "evidence/" + chr(127) + "output.bin"

    assert list(json_schema_validator.iter_errors(manifest))


def test_json_schema_rejects_whitespace_only_path(
    valid_manifest,
    json_schema_validator,
):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["path"] = "   "

    assert list(json_schema_validator.iter_errors(manifest))










def test_json_schema_rejects_invalid_sha256(
    valid_manifest,
    json_schema_validator,
):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["hash"]["value"] = "not-a-hash"

    errors = list(json_schema_validator.iter_errors(manifest))

    assert errors


def test_json_schema_rejects_timed_out_command_with_exit_code(
    valid_manifest,
    json_schema_validator,
):
    manifest = deepcopy(valid_manifest)
    command = manifest["commands"][0]
    command["timed_out"] = True
    command["execution_status"] = "TIMED_OUT"
    command["exit_code"] = 0

    errors = list(json_schema_validator.iter_errors(manifest))

    assert errors


def test_json_schema_rejects_completed_command_without_exit_code(
    valid_manifest,
    json_schema_validator,
):
    manifest = deepcopy(valid_manifest)
    command = manifest["commands"][0]
    command["exit_code"] = None

    errors = list(json_schema_validator.iter_errors(manifest))

    assert errors


def test_json_schema_rejects_duplicate_artifact_references(
    valid_manifest,
    json_schema_validator,
):
    manifest = deepcopy(valid_manifest)
    manifest["commands"][0]["artifact_ids"].append(
        manifest["commands"][0]["artifact_ids"][0]
    )

    errors = list(json_schema_validator.iter_errors(manifest))

    assert errors


def test_json_schema_rejects_timestamp_without_timezone(
    valid_manifest,
    json_schema_validator,
):
    manifest = deepcopy(valid_manifest)
    manifest["collection"]["started_utc"] = "2026-11-15T08:31:14"

    errors = list(json_schema_validator.iter_errors(manifest))

    assert errors


def test_integrated_validator_rejects_unknown_top_level_property(
    valid_manifest,
):
    manifest = deepcopy(valid_manifest)
    manifest["unexpected"] = True

    assert validate_manifest(manifest)


def test_integrated_validator_rejects_duplicate_artifact_references(
    valid_manifest,
):
    manifest = deepcopy(valid_manifest)
    refs = manifest["commands"][0]["artifact_ids"]
    refs.append(refs[0])

    errors = validate_manifest(manifest)

    assert any("duplicate reference" in error for error in errors)


def test_integrated_validator_rejects_empty_artifact_reference(
    valid_manifest,
):
    manifest = deepcopy(valid_manifest)
    manifest["commands"][0]["artifact_ids"][0] = ""

    assert validate_manifest(manifest)


def test_integrated_validator_rejects_windows_drive_path(
    valid_manifest,
):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["path"] = "C:/evidence/output.bin"

    assert validate_manifest(manifest)


def test_integrated_validator_rejects_control_character_in_path(
    valid_manifest,
):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["path"] = "evidence/\x01output.bin"

    assert validate_manifest(manifest)


def test_integrated_validator_rejects_del_in_path(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["path"] = "evidence/" + chr(127) + "output.bin"

    assert validate_manifest(manifest)


def test_integrated_validator_rejects_whitespace_only_path(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["artifacts"][0]["path"] = "   "

    assert validate_manifest(manifest)










def test_integrated_validator_rejects_non_rfc3339_timestamp(
    valid_manifest,
):
    manifest = deepcopy(valid_manifest)
    manifest["collection"]["started_utc"] = (
        "2026-11-15 08:31:14+00:00"
    )

    assert validate_manifest(manifest)


def test_schema_resource_is_available_from_installed_package():
    from importlib.resources import files

    schema_resource = files("ose").joinpath(
        "schemas",
        "evidence-2.0.schema.json",
    )

    assert schema_resource.is_file()


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("collection", "status"),
        ("identity", "status"),
        ("capture", "status"),
        ("assessment", "status"),
    ],
)
@pytest.mark.parametrize("invalid_value", [[], {}, None])
def test_rejects_non_string_status_values(
    valid_manifest,
    section,
    field,
    invalid_value,
):
    manifest = deepcopy(valid_manifest)
    manifest[section][field] = invalid_value

    errors = validate_manifest(manifest)

    assert errors
    assert any(section in error for error in errors)


@pytest.mark.parametrize("invalid_value", [[], {}, None])
def test_rejects_non_string_command_execution_status(
    valid_manifest,
    invalid_value,
):
    manifest = deepcopy(valid_manifest)
    manifest["commands"][0]["execution_status"] = invalid_value

    errors = validate_manifest(manifest)

    assert errors
    assert any(
        "execution_status" in error
        for error in errors
    )


def test_rejects_extremely_large_integer_duration(valid_manifest):
    manifest = deepcopy(valid_manifest)
    manifest["commands"][0]["duration_seconds"] = 10**10000

    errors = validate_manifest(manifest)

    assert errors
    assert any(
        "duration_seconds" in error
        for error in errors
    )
