import hashlib

import pytest

from cryptography.hazmat.primitives import serialization

from ose.crypto import generate_key_pair
from ose.packager import create_package
from ose.report import generate_report


def make_package(tmp_path, schema_2=False):
    from test_packager import make_schema_2_collection

    source = tmp_path / "source"
    package = tmp_path / "package"
    keys = tmp_path / "keys"
    keys.mkdir()

    if schema_2:
        make_schema_2_collection(source)
    else:
        source.mkdir()
        (source / "operation.log").write_text(
            "Test evidence\n",
            encoding="utf-8",
        )

    private_key = keys / "private.pem"
    public_key = keys / "public.pem"

    generate_key_pair(private_key, public_key)
    create_package(source, package, private_key)

    return package, private_key, public_key


def assert_valid_pdf(path):
    assert path.is_file()
    content = path.read_bytes()
    assert content.startswith(b"%PDF-")
    assert len(content) > 1000


def test_generate_report_for_generic_package(tmp_path):
    package, _, public_key = make_package(tmp_path)
    output = tmp_path / "audit.pdf"

    result = generate_report(package, public_key, output)

    assert_valid_pdf(output)
    assert result["integrity_valid"] is True
    assert result["assessment_status"] == "NOT_ASSESSED"
    assert result["collection_id"] is None


def test_generate_report_for_schema_2_collection(tmp_path):
    package, _, public_key = make_package(tmp_path, schema_2=True)
    output = tmp_path / "audit.pdf"

    result = generate_report(
        package,
        public_key,
        output,
        operation={
            "status": "COMPLETED",
            "technique": "PURGE",
            "verification": {"status": "PASSED"},
            "validation": {"status": "PASSED"},
        },
    )

    assert_valid_pdf(output)
    assert result["integrity_valid"] is True
    assert result["assessment_status"] == "UNDER_REVIEW"
    assert result["collection_id"] == "package-test-collection"


def test_tampered_package_generates_failure_report(tmp_path):
    package, _, public_key = make_package(tmp_path)

    evidence = package / "evidence" / "operation.log"
    evidence.write_text("Tampered evidence\n", encoding="utf-8")

    output = tmp_path / "failure.pdf"

    result = generate_report(package, public_key, output)

    assert_valid_pdf(output)
    assert result["integrity_valid"] is False
    assert result["assessment_status"] == "NOT_ASSESSED"


def test_malformed_public_key_generates_failure_report(tmp_path):
    package, _, public_key = make_package(tmp_path)

    public_key.write_text("not a valid public key", encoding="ascii")
    output = tmp_path / "failure.pdf"

    result = generate_report(package, public_key, output)

    assert_valid_pdf(output)
    assert result["integrity_valid"] is False
    assert result["assessment_status"] == "NOT_ASSESSED"


def test_report_does_not_overwrite_existing_output(tmp_path):
    package, _, public_key = make_package(tmp_path)
    output = tmp_path / "existing.pdf"
    original = b"Do not overwrite this file."
    output.write_bytes(original)

    with pytest.raises(FileExistsError):
        generate_report(package, public_key, output)

    assert output.read_bytes() == original


def test_report_cannot_be_written_inside_package(tmp_path):
    package, _, public_key = make_package(tmp_path)
    output = package / "audit.pdf"

    with pytest.raises(ValueError, match="inside the evidence package"):
        generate_report(package, public_key, output)

    assert not output.exists()


def test_report_output_directory_must_exist(tmp_path):
    package, _, public_key = make_package(tmp_path)
    output = tmp_path / "missing" / "audit.pdf"

    with pytest.raises(ValueError, match="output directory"):
        generate_report(package, public_key, output)


def test_public_key_fingerprint_uses_der_spki(tmp_path, monkeypatch):
    package, _, public_key = make_package(tmp_path)
    output = tmp_path / "fingerprint.pdf"

    from ose import report

    captured_rows = []
    original_table = report._key_value_table

    def capture_table(rows, styles):
        captured_rows.extend(rows)
        return original_table(rows, styles)

    monkeypatch.setattr(report, "_key_value_table", capture_table)

    loaded_key = serialization.load_pem_public_key(
        public_key.read_bytes()
    )
    der = loaded_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected = hashlib.sha256(der).hexdigest()

    generate_report(package, public_key, output)

    assert ("Public key DER SHA-256", expected) in captured_rows
