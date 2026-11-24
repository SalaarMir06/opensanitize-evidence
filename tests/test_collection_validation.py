import json
import hashlib

import pytest

from ose.collection_validation import validate_collection_directory


def make_collection(tmp_path):
    root = tmp_path / "collection"
    root.mkdir()

    content = b"raw evidence bytes"
    artifact = root / "command.stdout.bin"
    artifact.write_bytes(content)

    manifest = {
        "schema_version": "2.0",
        "collection": {
            "collection_id": "test-collection",
            "collector": "OSE test collector",
            "adapter": "test",
            "started_utc": "2026-01-01T10:00:00Z",
            "finished_utc": "2026-01-01T10:01:00Z",
            "status": "COMPLETE",
        },
        "target": {
            "expected_identity": {"serial": "TEST-123"},
            "observations": {"before": None, "after": None},
        },
        "identity": {"status": "VERIFIED", "checks": {}},
        "commands": [{
            "command_id": "cmd-test",
            "name": "test",
            "argv": ["test-tool", "--version"],
            "started_utc": "2026-01-01T10:00:00Z",
            "finished_utc": "2026-01-01T10:00:01Z",
            "duration_seconds": 1.0,
            "exit_code": 0,
            "timed_out": False,
            "execution_status": "COMPLETED",
            "artifact_ids": ["test-stdout"],
            "extensions": {},
        }],
        "artifacts": [{
            "artifact_id": "test-stdout",
            "role": "stdout",
            "path": "command.stdout.bin",
            "media_type": "application/octet-stream",
            "size_bytes": len(content),
            "hash": {
                "algorithm": "sha256",
                "value": hashlib.sha256(content).hexdigest(),
            },
        }],
        "capture": {"status": "COMPLETE"},
        "assessment": {"status": "NOT_ASSESSED"},
        "safety": {
            "read_only_collection": True,
            "destructive_commands_executed": False,
        },
        "extensions": {"test": {}},
    }

    (root / "collection.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    return root


def test_valid_collection_directory_passes(tmp_path):
    root = make_collection(tmp_path)

    manifest = validate_collection_directory(root)

    assert manifest["schema_version"] == "2.0"


def test_modified_artifact_is_rejected(tmp_path):
    root = make_collection(tmp_path)
    (root / "command.stdout.bin").write_bytes(b"modified")

    with pytest.raises(ValueError, match="size mismatch|SHA-256 mismatch"):
        validate_collection_directory(root)


def test_unlisted_file_is_rejected(tmp_path):
    root = make_collection(tmp_path)
    (root / "unexpected.bin").write_bytes(b"unexpected")

    with pytest.raises(ValueError, match="Unexpected collection files"):
        validate_collection_directory(root)


def test_missing_artifact_is_rejected(tmp_path):
    root = make_collection(tmp_path)
    (root / "command.stdout.bin").unlink()

    with pytest.raises(ValueError, match="Missing or unsafe collection artifact"):
        validate_collection_directory(root)


def test_unlisted_directory_is_rejected(tmp_path):
    root = make_collection(tmp_path)
    (root / "unexpected").mkdir()

    with pytest.raises(ValueError, match="Unlisted collection directories"):
        validate_collection_directory(root)


def test_symlink_artifact_is_rejected(tmp_path):
    root = make_collection(tmp_path)
    target = tmp_path / "outside.bin"
    target.write_bytes(b"outside")
    (root / "command.stdout.bin").unlink()
    (root / "command.stdout.bin").symlink_to(target)

    with pytest.raises(ValueError, match="Symbolic link"):
        validate_collection_directory(root)


def test_invalid_manifest_is_rejected(tmp_path):
    root = make_collection(tmp_path)
    manifest = json.loads((root / "collection.json").read_text())
    manifest["schema_version"] = "1.0"
    (root / "collection.json").write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="Invalid OSE Evidence Schema"):
        validate_collection_directory(root)
