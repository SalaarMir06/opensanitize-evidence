"""Validation utilities for OSE Evidence Schema 2.0."""

import json
import math
import re
from datetime import datetime
from importlib.resources import files
from pathlib import PurePosixPath

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_VERSION = "2.0"


# Load the packaged Schema 2.0 definition.
_SCHEMA_RESOURCE = files("ose").joinpath(
    "schemas",
    "evidence-2.0.schema.json",
)

with _SCHEMA_RESOURCE.open("r", encoding="utf-8") as schema_file:
    _SCHEMA = json.load(schema_file)

Draft202012Validator.check_schema(_SCHEMA)

_SCHEMA_VALIDATOR = Draft202012Validator(
    _SCHEMA,
    format_checker=FormatChecker(),
)

COLLECTION_STATUSES = {
    "COMPLETE",
    "INCOMPLETE",
}

CAPTURE_STATUSES = {
    "COMPLETE",
    "PARTIAL",
    "INCOMPLETE",
}

IDENTITY_STATUSES = {
    "VERIFIED",
    "FAILED",
    "NOT_CHECKED",
}

COMMAND_STATUSES = {
    "COMPLETED",
    "TIMED_OUT",
}

ASSESSMENT_STATUSES = {
    "NOT_ASSESSED",
    "UNDER_REVIEW",
    "CONFORMANT",
    "NON_CONFORMANT",
    "INCONCLUSIVE",
}

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _parse_timestamp(value):
    """Parse an ISO-8601 timestamp, requiring timezone information."""
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    return parsed


def _is_timestamp(value):
    """Require an ISO-8601 timestamp with timezone information."""
    return _parse_timestamp(value) is not None


def _is_safe_artifact_path(value):
    """Accept only normalized relative POSIX paths."""
    if not isinstance(value, str) or not value.strip():
        return False

    if "\\" in value:
        return False

    if re.match(r"^[A-Za-z]:", value):
        return False

    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False

    path = PurePosixPath(value)

    if path.is_absolute():
        return False

    if any(part in {"", ".", ".."} for part in value.split("/")):
        return False

    return True


def validate_manifest(manifest):
    """Return a list of validation errors for an OSE 2.0 manifest.

    This validator checks the common structural contract and cross-references.
    Utility-specific extension contents are preserved but are not interpreted.
    """
    errors = []

    def require_object(parent, key, location):
        value = parent.get(key) if isinstance(parent, dict) else None
        if not isinstance(value, dict):
            errors.append(f"{location}.{key} must be an object")
            return None
        return value

    def require_string(parent, key, location):
        value = parent.get(key) if isinstance(parent, dict) else None
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{location}.{key} must be a non-empty string")
            return None
        return value

    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]

    schema_errors = sorted(
        _SCHEMA_VALIDATOR.iter_errors(manifest),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            error.message,
        ),
    )

    for error in schema_errors:
        location = ".".join(
            str(part) for part in error.absolute_path
        ) or "manifest"
        errors.append(f"{location}: {error.message}")

    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION!r}"
        )

    collection = require_object(manifest, "collection", "manifest")

    if collection is not None:
        require_string(collection, "collection_id", "collection")
        require_string(collection, "collector", "collection")
        require_string(collection, "adapter", "collection")

        collection_times = {}
        for field in ("started_utc", "finished_utc"):
            parsed = _parse_timestamp(collection.get(field))
            if parsed is None:
                errors.append(
                    f"collection.{field} must be an ISO-8601 "
                    "timestamp with timezone"
                )
            else:
                collection_times[field] = parsed

        if (
            "started_utc" in collection_times
            and "finished_utc" in collection_times
            and collection_times["started_utc"]
            > collection_times["finished_utc"]
        ):
            errors.append(
                "collection.started_utc must not be later than "
                "collection.finished_utc"
            )

        if not isinstance(collection.get("status"), str) or collection.get("status") not in COLLECTION_STATUSES:
            errors.append("collection.status is invalid")

    target = require_object(manifest, "target", "manifest")

    if target is not None:
        expected = require_object(
            target, "expected_identity", "target"
        )
        if expected is not None:
            require_string(expected, "serial", "target.expected_identity")

        observations = require_object(
            target, "observations", "target"
        )
        if observations is not None:
            for field in ("before", "after"):
                value = observations.get(field)
                if value is not None and not isinstance(value, dict):
                    errors.append(
                        f"target.observations.{field} must be an object or null"
                    )

    identity = require_object(manifest, "identity", "manifest")

    if identity is not None:
        if not isinstance(identity.get("status"), str) or identity.get("status") not in IDENTITY_STATUSES:
            errors.append("identity.status is invalid")

        if not isinstance(identity.get("checks"), dict):
            errors.append("identity.checks must be an object")

    capture = require_object(manifest, "capture", "manifest")

    if capture is not None:
        if not isinstance(capture.get("status"), str) or capture.get("status") not in CAPTURE_STATUSES:
            errors.append("capture.status is invalid")

    assessment = require_object(manifest, "assessment", "manifest")

    if assessment is not None:
        if not isinstance(assessment.get("status"), str) or assessment.get("status") not in ASSESSMENT_STATUSES:
            errors.append("assessment.status is invalid")

    safety = require_object(manifest, "safety", "manifest")

    if safety is not None:
        for field in (
            "read_only_collection",
            "destructive_commands_executed",
        ):
            if not isinstance(safety.get(field), bool):
                errors.append(f"safety.{field} must be a boolean")

    extensions = manifest.get("extensions")
    if not isinstance(extensions, dict):
        errors.append("extensions must be an object")

    commands = manifest.get("commands")
    artifacts = manifest.get("artifacts")

    if not isinstance(commands, list):
        errors.append("commands must be an array")
        commands = []

    if not isinstance(artifacts, list):
        errors.append("artifacts must be an array")
        artifacts = []

    command_ids = set()
    artifact_ids = set()
    artifact_paths = set()
    referenced_artifacts = []

    for index, command in enumerate(commands):
        location = f"commands[{index}]"

        if not isinstance(command, dict):
            errors.append(f"{location} must be an object")
            continue

        command_id = require_string(command, "command_id", location)

        if command_id is not None:
            if command_id in command_ids:
                errors.append(f"duplicate command_id: {command_id}")
            command_ids.add(command_id)

        require_string(command, "name", location)

        argv = command.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(arg, str) for arg in argv)
        ):
            errors.append(f"{location}.argv must be a non-empty string array")

        command_times = {}
        for field in ("started_utc", "finished_utc"):
            parsed = _parse_timestamp(command.get(field))
            if parsed is None:
                errors.append(
                    f"{location}.{field} must be an ISO-8601 "
                    "timestamp with timezone"
                )
            else:
                command_times[field] = parsed

        if (
            "started_utc" in command_times
            and "finished_utc" in command_times
            and command_times["started_utc"]
            > command_times["finished_utc"]
        ):
            errors.append(
                f"{location}.started_utc must not be later than "
                "finished_utc"
            )

        duration = command.get("duration_seconds")
        duration_is_valid = (
            not isinstance(duration, bool)
            and isinstance(duration, (int, float))
            and duration >= 0
        )

        if duration_is_valid:
            try:
                duration_is_valid = math.isfinite(duration)
            except OverflowError:
                duration_is_valid = False

        if not duration_is_valid:
            errors.append(
                f"{location}.duration_seconds must be a finite "
                "non-negative number"
            )

        exit_code = command.get("exit_code")
        if exit_code is not None and (
            isinstance(exit_code, bool) or not isinstance(exit_code, int)
        ):
            errors.append(f"{location}.exit_code must be an integer or null")

        timed_out = command.get("timed_out")
        if not isinstance(timed_out, bool):
            errors.append(f"{location}.timed_out must be a boolean")

        execution_status = command.get("execution_status")
        if not isinstance(execution_status, str) or execution_status not in COMMAND_STATUSES:
            errors.append(f"{location}.execution_status is invalid")

        if isinstance(timed_out, bool) and isinstance(execution_status, str) and execution_status in COMMAND_STATUSES:
            if timed_out != (execution_status == "TIMED_OUT"):
                errors.append(
                    f"{location}.timed_out conflicts with execution_status"
                )

        if timed_out is True and exit_code is not None:
            errors.append(
                f"{location}.exit_code must be null when timed_out is true"
            )

        if timed_out is False and exit_code is None:
            errors.append(
                f"{location}.exit_code cannot be null when timed_out is false"
            )

        refs = command.get("artifact_ids")
        if not isinstance(refs, list):
            errors.append(f"{location}.artifact_ids must be a string array")
        else:
            seen_refs = set()

            for ref in refs:
                if not isinstance(ref, str) or not ref.strip():
                    errors.append(
                        f"{location}.artifact_ids must contain "
                        "non-empty strings"
                    )
                    continue

                if ref in seen_refs:
                    errors.append(
                        f"{location}.artifact_ids contains duplicate "
                        f"reference: {ref}"
                    )
                    continue

                seen_refs.add(ref)
                referenced_artifacts.append(ref)

        if not isinstance(command.get("extensions"), dict):
            errors.append(f"{location}.extensions must be an object")

    for index, artifact in enumerate(artifacts):
        location = f"artifacts[{index}]"

        if not isinstance(artifact, dict):
            errors.append(f"{location} must be an object")
            continue

        artifact_id = require_string(artifact, "artifact_id", location)

        if artifact_id is not None:
            if artifact_id in artifact_ids:
                errors.append(f"duplicate artifact_id: {artifact_id}")
            artifact_ids.add(artifact_id)

        require_string(artifact, "role", location)

        path = artifact.get("path")
        if not _is_safe_artifact_path(path):
            errors.append(f"{location}.path must be a safe relative path")
        elif path in artifact_paths:
            errors.append(f"duplicate artifact path: {path}")
        else:
            artifact_paths.add(path)

        require_string(artifact, "media_type", location)

        size = artifact.get("size_bytes")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            errors.append(
                f"{location}.size_bytes must be a non-negative integer"
            )

        hash_data = artifact.get("hash")
        if not isinstance(hash_data, dict):
            errors.append(f"{location}.hash must be an object")
        else:
            if hash_data.get("algorithm") != "sha256":
                errors.append(
                    f"{location}.hash.algorithm must be 'sha256'"
                )

            digest = hash_data.get("value")
            if (
                not isinstance(digest, str)
                or not SHA256_PATTERN.fullmatch(digest)
            ):
                errors.append(
                    f"{location}.hash.value must be a 64-character "
                    "lowercase SHA-256 hexadecimal digest"
                )

    for reference in referenced_artifacts:
        if reference not in artifact_ids:
            errors.append(
                f"command references unknown artifact_id: {reference}"
            )

    for artifact_id in artifact_ids:
        if artifact_id not in referenced_artifacts:
            errors.append(
                f"artifact is not referenced by any command: {artifact_id}"
            )

    return errors


def assert_valid_manifest(manifest):
    """Raise ValueError if a manifest does not satisfy the common contract."""
    errors = validate_manifest(manifest)

    if errors:
        raise ValueError(
            "Invalid OSE Evidence Schema 2.0 manifest:\n- "
            + "\n- ".join(errors)
        )
