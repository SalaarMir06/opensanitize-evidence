import json

from ose.cli import main
from ose.crypto import generate_key_pair
from ose.packager import create_package


def make_package(tmp_path):
    source = tmp_path / "source"
    package = tmp_path / "package"
    keys = tmp_path / "keys"

    source.mkdir()
    keys.mkdir()

    (source / "operation.log").write_text(
        "CLI report test evidence\\n",
        encoding="utf-8",
    )

    private_key = keys / "private.pem"
    public_key = keys / "public.pem"

    generate_key_pair(private_key, public_key)
    create_package(source, package, private_key)

    return package, public_key


def report_arguments(package, public_key, output):
    return [
        "report",
        "--input", str(package),
        "--public-key", str(public_key),
        "--output", str(output),
    ]


def test_cli_report_generates_pdf_for_valid_package(tmp_path, capsys):
    package, public_key = make_package(tmp_path)
    output = tmp_path / "audit.pdf"

    exit_code = main(report_arguments(package, public_key, output))

    captured = capsys.readouterr()

    assert exit_code == 0
    assert output.is_file()
    assert output.read_bytes().startswith(b"%PDF-")
    assert "INTEGRITY CHECK: PASSED" in captured.out
    assert "NOT_ASSESSED" in captured.out


def test_cli_report_generates_failure_pdf_and_returns_one(
    tmp_path,
    capsys,
):
    package, public_key = make_package(tmp_path)

    evidence = package / "evidence" / "operation.log"
    evidence.write_text("Tampered evidence\\n", encoding="utf-8")

    output = tmp_path / "failure.pdf"

    exit_code = main(report_arguments(package, public_key, output))

    captured = capsys.readouterr()

    assert exit_code == 1
    assert output.is_file()
    assert output.read_bytes().startswith(b"%PDF-")
    assert "INTEGRITY CHECK: FAILED" in captured.out
    assert '"integrity_valid": false' in captured.out


def test_cli_report_accepts_separate_operation_evidence(
    tmp_path,
    capsys,
):
    package, public_key = make_package(tmp_path)
    output = tmp_path / "audit.pdf"
    operation_path = tmp_path / "operation.json"

    operation_path.write_text(
        json.dumps({
            "status": "COMPLETED",
            "technique": "PURGE",
            "verification": {"status": "PASSED"},
            "validation": {"status": "PASSED"},
        }),
        encoding="utf-8",
    )

    arguments = report_arguments(package, public_key, output)
    arguments.extend(["--operation", str(operation_path)])

    exit_code = main(arguments)

    captured = capsys.readouterr()

    assert exit_code == 0
    assert output.is_file()
    assert '"assessment_status": "NOT_ASSESSED"' in captured.out


def test_cli_report_rejects_non_object_operation_json(
    tmp_path,
    capsys,
):
    package, public_key = make_package(tmp_path)
    output = tmp_path / "audit.pdf"
    operation_path = tmp_path / "operation.json"

    operation_path.write_text('["invalid", "root"]', encoding="utf-8")

    arguments = report_arguments(package, public_key, output)
    arguments.extend(["--operation", str(operation_path)])

    exit_code = main(arguments)

    captured = capsys.readouterr()

    assert exit_code == 2
    assert not output.exists()
    assert "Operation evidence JSON must contain an object." in captured.err


def test_cli_report_rejects_malformed_operation_json(
    tmp_path,
    capsys,
):
    package, public_key = make_package(tmp_path)
    output = tmp_path / "audit.pdf"
    operation_path = tmp_path / "operation.json"

    operation_path.write_text("{invalid json", encoding="utf-8")

    arguments = report_arguments(package, public_key, output)
    arguments.extend(["--operation", str(operation_path)])

    exit_code = main(arguments)

    captured = capsys.readouterr()

    assert exit_code == 2
    assert not output.exists()
    assert "Error:" in captured.err


def test_cli_report_does_not_overwrite_existing_output(
    tmp_path,
    capsys,
):
    package, public_key = make_package(tmp_path)
    output = tmp_path / "existing.pdf"
    original = b"Existing report must remain unchanged."
    output.write_bytes(original)

    exit_code = main(report_arguments(package, public_key, output))

    captured = capsys.readouterr()

    assert exit_code == 2
    assert output.read_bytes() == original
    assert "Error:" in captured.err
