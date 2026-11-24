import json
from ose.crypto import generate_key_pair
from ose.packager import create_package
from ose.verifier import verify_package


def make_package(tmp_path):
    source = tmp_path / "source"
    package = tmp_path / "package"
    keys = tmp_path / "keys"

    source.mkdir()
    keys.mkdir()

    (source / "operation.log").write_text(
        "Test sanitization evidence\n",
        encoding="utf-8",
    )

    private_key = keys / "private.pem"
    public_key = keys / "public.pem"

    generate_key_pair(private_key, public_key)
    create_package(source, package, private_key)

    return package, public_key


def test_valid_package_passes(tmp_path):
    package, public_key = make_package(tmp_path)

    result = verify_package(package, public_key)

    assert result["valid"] is True
    assert result["checked_files"] == 1
    assert result["errors"] == []


def test_modified_evidence_is_detected(tmp_path):
    package, public_key = make_package(tmp_path)

    evidence_file = package / "evidence" / "operation.log"
    evidence_file.write_text("Modified evidence\n", encoding="utf-8")

    result = verify_package(package, public_key)

    assert result["valid"] is False
    assert any("mismatch" in error for error in result["errors"])


def test_missing_evidence_is_detected(tmp_path):
    package, public_key = make_package(tmp_path)

    (package / "evidence" / "operation.log").unlink()

    result = verify_package(package, public_key)

    assert result["valid"] is False
    assert any("Missing" in error for error in result["errors"])


def test_unlisted_evidence_is_detected(tmp_path):
    package, public_key = make_package(tmp_path)

    extra_file = package / "evidence" / "unexpected.log"
    extra_file.write_text("Unlisted file\n", encoding="utf-8")

    result = verify_package(package, public_key)

    assert result["valid"] is False
    assert any("Unexpected" in error for error in result["errors"])


def test_modified_manifest_is_detected(tmp_path):
    package, public_key = make_package(tmp_path)

    manifest = package / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")

    result = verify_package(package, public_key)

    assert result["valid"] is False
    assert any("signature" in error.lower() for error in result["errors"])


def test_valid_schema_2_collection_package_passes(tmp_path):
    from test_packager import make_schema_2_collection

    source = tmp_path / "collection"
    package = tmp_path / "package"
    keys = tmp_path / "keys"
    keys.mkdir()

    make_schema_2_collection(source)

    private_key = keys / "private.pem"
    public_key = keys / "public.pem"
    generate_key_pair(private_key, public_key)
    create_package(source, package, private_key)

    result = verify_package(package, public_key)

    assert result["valid"] is True
    assert result["checked_files"] == 2
    assert result["errors"] == []


def test_modified_collection_artifact_fails_verification(tmp_path):
    from test_packager import make_schema_2_collection

    source = tmp_path / "collection"
    package = tmp_path / "package"
    keys = tmp_path / "keys"
    keys.mkdir()

    make_schema_2_collection(source)

    private_key = keys / "private.pem"
    public_key = keys / "public.pem"
    generate_key_pair(private_key, public_key)
    create_package(source, package, private_key)

    artifact = package / "evidence" / "command.stdout.bin"
    artifact.write_bytes(b"tampered")

    result = verify_package(package, public_key)

    assert result["valid"] is False
    assert any("mismatch" in error.lower() for error in result["errors"])


def test_invalid_embedded_collection_manifest_fails_verification(tmp_path):
    from test_packager import make_schema_2_collection
    from ose.packager import canonical_json
    from ose.crypto import sign_data

    source = tmp_path / "collection"
    package = tmp_path / "package"
    keys = tmp_path / "keys"
    keys.mkdir()

    make_schema_2_collection(source)

    private_key = keys / "private.pem"
    public_key = keys / "public.pem"
    generate_key_pair(private_key, public_key)
    create_package(source, package, private_key)

    collection_path = package / "evidence" / "collection.json"
    collection = json.loads(collection_path.read_text(encoding="utf-8"))
    collection["schema_version"] = "1.0"
    collection_path.write_text(json.dumps(collection), encoding="utf-8")

    package_manifest_path = package / "manifest.json"
    package_manifest = json.loads(
        package_manifest_path.read_bytes()
    )
    package_manifest["evidence_files"] = [
        {
            **entry,
            "sha256": __import__("hashlib").sha256(
                (package / "evidence" / entry["path"]).read_bytes()
            ).hexdigest(),
            "size_bytes": (
                package / "evidence" / entry["path"]
            ).stat().st_size,
        }
        if entry["path"] == "collection.json"
        else entry
        for entry in package_manifest["evidence_files"]
    ]

    manifest_bytes = canonical_json(package_manifest)
    package_manifest_path.write_bytes(manifest_bytes)
    (package / "manifest.sig").write_text(
        sign_data(manifest_bytes, private_key) + "\n",
        encoding="ascii",
    )

    result = verify_package(package, public_key)

    assert result["valid"] is False
    assert any(
        "Collection validation failed" in error
        for error in result["errors"]
    )


def test_symbolic_link_package_root_is_rejected(tmp_path):
    package, public_key = make_package(tmp_path)
    package_link = tmp_path / "package-link"
    package_link.symlink_to(package, target_is_directory=True)

    result = verify_package(package_link, public_key)

    assert result["valid"] is False


def test_symbolic_link_manifest_is_rejected(tmp_path):
    package, public_key = make_package(tmp_path)
    manifest = package / "manifest.json"
    original = package / "manifest-original.json"

    manifest.rename(original)
    manifest.symlink_to(original)

    result = verify_package(package, public_key)

    assert result["valid"] is False


def test_symbolic_link_signature_is_rejected(tmp_path):
    package, public_key = make_package(tmp_path)
    signature = package / "manifest.sig"
    original = package / "signature-original.sig"

    signature.rename(original)
    signature.symlink_to(original)

    result = verify_package(package, public_key)

    assert result["valid"] is False


def test_fifo_in_evidence_directory_is_rejected(tmp_path):
    import os

    package, public_key = make_package(tmp_path)
    fifo = package / "evidence" / "unexpected.fifo"
    os.mkfifo(fifo)

    result = verify_package(package, public_key)

    assert result["valid"] is False


def test_symbolic_link_nested_evidence_directory_is_rejected(tmp_path):
    package, public_key = make_package(tmp_path)

    evidence_dir = package / "evidence"
    nested_dir = evidence_dir / "nested"
    nested_dir.mkdir()

    (nested_dir / "extra.log").write_text(
        "Unexpected evidence\n",
        encoding="utf-8",
    )

    external_dir = tmp_path / "external"
    external_dir.mkdir()

    nested_dir.rename(external_dir)
    nested_dir.symlink_to(external_dir, target_is_directory=True)

    result = verify_package(package, public_key)

    assert result["valid"] is False
    assert any(
        "Symbolic link" in error
        for error in result["errors"]
    )


def test_symbolic_link_public_key_is_rejected(tmp_path):
    package, public_key = make_package(tmp_path)

    original_key = tmp_path / "original-public.pem"
    public_key.rename(original_key)
    public_key.symlink_to(original_key)

    result = verify_package(package, public_key)

    assert result["valid"] is False
