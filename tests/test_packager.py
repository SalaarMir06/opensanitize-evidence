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
