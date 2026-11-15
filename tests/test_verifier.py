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
