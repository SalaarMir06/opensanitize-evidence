import json

from ose.crypto import generate_key_pair
from ose.packager import create_package


def test_create_evidence_package(tmp_path):
    evidence_dir = tmp_path / "source"
    output_dir = tmp_path / "package"
    keys_dir = tmp_path / "keys"

    evidence_dir.mkdir()
    keys_dir.mkdir()

    (evidence_dir / "operation.log").write_text(
        "Sanitization operation test log\n",
        encoding="utf-8",
    )

    private_key = keys_dir / "private.pem"
    public_key = keys_dir / "public.pem"
    generate_key_pair(private_key, public_key)

    metadata = {
        "device_model": "TEST DEVICE",
        "serial_number": "TEST-12345",
        "sanitization_method": "TEST ONLY",
    }

    manifest = create_package(
        evidence_dir,
        output_dir,
        private_key,
        metadata,
    )

    assert manifest["schema_version"] == "1.0"
    assert len(manifest["evidence_files"]) == 1
    assert manifest["metadata"] == metadata

    assert (output_dir / "manifest.json").exists()
    assert (output_dir / "manifest.sig").exists()
    assert (output_dir / "evidence" / "operation.log").exists()

    saved_manifest = json.loads(
        (output_dir / "manifest.json").read_text(encoding="utf-8")
    )

    assert saved_manifest == manifest


def test_source_evidence_is_not_modified(tmp_path):
    evidence_dir = tmp_path / "source"
    output_dir = tmp_path / "package"
    keys_dir = tmp_path / "keys"

    evidence_dir.mkdir()
    keys_dir.mkdir()

    original_content = b"Original evidence content"
    source_file = evidence_dir / "operation.log"
    source_file.write_bytes(original_content)

    private_key = keys_dir / "private.pem"
    public_key = keys_dir / "public.pem"
    generate_key_pair(private_key, public_key)

    create_package(evidence_dir, output_dir, private_key)

    assert source_file.read_bytes() == original_content


def make_schema_2_collection(root):
    import hashlib

    root.mkdir()
    content = b"schema 2 collection evidence"
    (root / "command.stdout.bin").write_bytes(content)

    manifest = {
        "schema_version": "2.0",
        "collection": {
            "collection_id": "package-test-collection",
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


def test_schema_2_collection_is_validated_and_packaged(tmp_path):
    evidence_dir = tmp_path / "collection"
    output_dir = tmp_path / "package"
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()

    make_schema_2_collection(evidence_dir)

    original_manifest = (evidence_dir / "collection.json").read_bytes()
    original_artifact = (evidence_dir / "command.stdout.bin").read_bytes()

    private_key = keys_dir / "private.pem"
    generate_key_pair(private_key, keys_dir / "public.pem")

    manifest = create_package(evidence_dir, output_dir, private_key)

    assert len(manifest["evidence_files"]) == 2
    assert (
        output_dir / "evidence" / "collection.json"
    ).read_bytes() == original_manifest
    assert (
        output_dir / "evidence" / "command.stdout.bin"
    ).read_bytes() == original_artifact

    assert (evidence_dir / "collection.json").read_bytes() == original_manifest
    assert (evidence_dir / "command.stdout.bin").read_bytes() == original_artifact


def test_invalid_schema_2_collection_is_rejected_before_packaging(tmp_path):
    import pytest

    evidence_dir = tmp_path / "collection"
    output_dir = tmp_path / "package"
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()

    make_schema_2_collection(evidence_dir)

    manifest_path = evidence_dir / "collection.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = "1.0"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    private_key = keys_dir / "private.pem"
    generate_key_pair(private_key, keys_dir / "public.pem")

    with pytest.raises(ValueError, match="Invalid OSE Evidence Schema"):
        create_package(evidence_dir, output_dir, private_key)

    assert not output_dir.exists()
