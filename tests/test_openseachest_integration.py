import hashlib
import json

import pytest

from collectors.openseachest import collector
from ose.evidence_schema import validate_manifest


EXPECTED_SERIAL = "TEST-SERIAL-0001"

SAT_OUTPUT = (
    b"SCSI Translator Reported Information:\n"
    b"Serial Number: 0000000000000000\n"
    b"\n"
    b"ATA Reported Information:\n"
    b"Serial Number: TEST-SERIAL-0001\n"
)

SCAN_OUTPUT = (
    b"Vendor Samsung /dev/sg0 "
    b"Samsung SSD 850 EVO 250GB "
    b"TEST-SERIAL-0001 EMT02B6Q\n"
)


def make_inventory(serial=EXPECTED_SERIAL, tran="usb"):
    return {
        "path": "/dev/sda",
        "type": "disk",
        "size": 250059350016,
        "model": "Samsung SSD 850 EVO 250GB",
        "serial": serial,
        "tran": tran,
    }


def make_record(
    argv,
    stdout=b"OK\n",
    stderr=b"",
    exit_code=0,
    timed_out=False,
):
    return {
        "started_utc": "2026-11-23T15:00:00+00:00",
        "finished_utc": "2026-11-23T15:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": argv,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
    }


def configure_collector(
    monkeypatch,
    inventories=None,
    failures=None,
    sat_output=SAT_OUTPUT,
    scan_output=SCAN_OUTPUT,
):
    monkeypatch.setattr(
        collector.shutil,
        "which",
        lambda name: {
            "openSeaChest_Info": "/usr/local/bin/openSeaChest_Info",
            "sudo": "/usr/bin/sudo",
        }.get(name),
    )

    inventory_results = list(
        inventories
        if inventories is not None
        else [make_inventory(), make_inventory()]
    )

    def fake_inventory(device):
        result = inventory_results.pop(0)

        if isinstance(result, Exception):
            raise result

        return result

    monkeypatch.setattr(
        collector,
        "get_device_inventory",
        fake_inventory,
    )

    failures = failures or {}

    def fake_run_command(argv, timeout=60):
        if "--version" in argv:
            name = "version"
            stdout = b"openSeaChest_Info version 26.03.2\n"
        elif "--scan" in argv:
            name = "usb_scan"
            stdout = scan_output
        elif "--SATInfo" in argv:
            name = "sat_info"
            stdout = sat_output
        else:
            name = "device_info"
            stdout = b"Samsung SSD 850 EVO 250GB\n"

        failure = failures.get(name)

        if failure == "timeout":
            return make_record(
                argv,
                stdout=b"Partial output",
                exit_code=None,
                timed_out=True,
            )

        if failure == "nonzero":
            return make_record(
                argv,
                stdout=stdout,
                stderr=b"Simulated command failure",
                exit_code=2,
            )

        return make_record(argv, stdout=stdout)

    monkeypatch.setattr(
        collector,
        "run_command",
        fake_run_command,
    )


def read_manifest(output):
    return json.loads(
        (output / "collection.json").read_text(encoding="utf-8")
    )


def assert_manifest_valid(evidence):
    errors = validate_manifest(evidence)
    assert errors == [], "\n".join(errors)


def assert_artifacts_valid(output, evidence):
    artifact_ids = {
        artifact["artifact_id"]
        for artifact in evidence["artifacts"]
    }

    for command in evidence["commands"]:
        assert len(command["artifact_ids"]) == 2
        assert set(command["artifact_ids"]).issubset(artifact_ids)

    for artifact in evidence["artifacts"]:
        data = (output / artifact["path"]).read_bytes()

        assert len(data) == artifact["size_bytes"]
        assert hashlib.sha256(data).hexdigest() == (
            artifact["hash"]["value"]
        )


def test_collect_success(monkeypatch, tmp_path):
    configure_collector(monkeypatch)
    output = tmp_path / "successful-collection"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    assert result == 0

    evidence = read_manifest(output)
    assert_manifest_valid(evidence)
    assert_artifacts_valid(output, evidence)

    assert evidence["schema_version"] == "2.0"
    assert evidence["collection"]["status"] == "COMPLETE"
    assert evidence["capture"]["status"] == "COMPLETE"
    assert evidence["identity"]["status"] == "VERIFIED"
    assert evidence["assessment"]["status"] == "NOT_ASSESSED"

    assert len(evidence["commands"]) == 4
    assert len(evidence["artifacts"]) == 8

    assert [
        command["name"] for command in evidence["commands"]
    ] == [
        "version",
        "usb_scan",
        "device_info",
        "sat_info",
    ]

    checks = evidence["identity"]["checks"]
    assert checks["linux_serial_before_matches"] is True
    assert checks["linux_serial_after_matches"] is True
    assert checks["usb_scan_contains_expected_serial"] is True
    assert checks["ata_serial_matches"] is True

    sat_artifact = next(
        artifact
        for artifact in evidence["artifacts"]
        if artifact["artifact_id"] == "sat_info-stdout"
    )

    assert (
        output / sat_artifact["path"]
    ).read_bytes() == SAT_OUTPUT

    assert evidence["safety"]["read_only_collection"] is True
    assert evidence["safety"]["destructive_commands_executed"] is False


def test_collect_preserves_nonzero_command_exit(
    monkeypatch, tmp_path
):
    configure_collector(
        monkeypatch,
        failures={"device_info": "nonzero"},
    )
    output = tmp_path / "nonzero-command"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    evidence = read_manifest(output)
    assert_manifest_valid(evidence)
    assert_artifacts_valid(output, evidence)

    command = next(
        item
        for item in evidence["commands"]
        if item["name"] == "device_info"
    )

    assert result == 1
    assert evidence["collection"]["status"] == "COMPLETE"
    assert evidence["capture"]["status"] == "COMPLETE"
    assert evidence["identity"]["status"] == "VERIFIED"
    assert command["exit_code"] == 2
    assert command["execution_status"] == "COMPLETED"
    assert command["extensions"]["exit_code_zero"] is False

    stderr = next(
        artifact
        for artifact in evidence["artifacts"]
        if artifact["artifact_id"] == "device_info-stderr"
    )
    assert (output / stderr["path"]).read_bytes() == (
        b"Simulated command failure"
    )


def test_collect_preserves_timeout_and_partial_output(
    monkeypatch, tmp_path
):
    configure_collector(
        monkeypatch,
        failures={"device_info": "timeout"},
    )
    output = tmp_path / "timeout-command"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    evidence = read_manifest(output)
    assert_manifest_valid(evidence)
    assert_artifacts_valid(output, evidence)

    command = next(
        item
        for item in evidence["commands"]
        if item["name"] == "device_info"
    )

    assert result == 1
    assert evidence["collection"]["status"] == "COMPLETE"
    assert evidence["capture"]["status"] == "COMPLETE"
    assert command["timed_out"] is True
    assert command["exit_code"] is None
    assert command["execution_status"] == "TIMED_OUT"

    stdout = next(
        artifact
        for artifact in evidence["artifacts"]
        if artifact["artifact_id"] == "device_info-stdout"
    )
    assert (output / stdout["path"]).read_bytes() == b"Partial output"


def test_collect_fails_when_ata_serial_does_not_match(
    monkeypatch, tmp_path
):
    wrong_output = SAT_OUTPUT.replace(
        EXPECTED_SERIAL.encode(),
        b"WRONG-SERIAL",
    )
    configure_collector(monkeypatch, sat_output=wrong_output)
    output = tmp_path / "wrong-ata-identity"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    evidence = read_manifest(output)
    assert_manifest_valid(evidence)

    assert result == 1
    assert evidence["collection"]["status"] == "COMPLETE"
    assert evidence["capture"]["status"] == "COMPLETE"
    assert evidence["identity"]["status"] == "FAILED"
    assert evidence["identity"]["checks"]["ata_serial_matches"] is False


def test_collect_fails_when_usb_scan_does_not_contain_serial(
    monkeypatch, tmp_path
):
    configure_collector(
        monkeypatch,
        scan_output=b"No matching Samsung device found\n",
    )
    output = tmp_path / "missing-usb-identity"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    evidence = read_manifest(output)
    assert_manifest_valid(evidence)

    assert result == 1
    assert evidence["identity"]["status"] == "FAILED"
    assert evidence["identity"]["checks"][
        "usb_scan_contains_expected_serial"
    ] is False


def test_collect_fails_when_post_collection_identity_changes(
    monkeypatch, tmp_path
):
    configure_collector(
        monkeypatch,
        inventories=[
            make_inventory(),
            make_inventory(serial="DIFFERENT-SERIAL"),
        ],
    )
    output = tmp_path / "changed-device-identity"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    evidence = read_manifest(output)
    assert_manifest_valid(evidence)

    assert result == 1
    assert evidence["collection"]["status"] == "COMPLETE"
    assert evidence["identity"]["status"] == "FAILED"
    assert evidence["identity"]["checks"][
        "linux_serial_after_matches"
    ] is False


def test_collect_records_post_inventory_error(
    monkeypatch, tmp_path
):
    configure_collector(
        monkeypatch,
        inventories=[
            make_inventory(),
            RuntimeError("Simulated post-inventory failure"),
        ],
    )
    output = tmp_path / "post-inventory-error"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    evidence = read_manifest(output)
    assert_manifest_valid(evidence)

    assert result == 1
    assert evidence["collection"]["status"] == "INCOMPLETE"
    assert evidence["identity"]["status"] == "FAILED"
    assert evidence["identity"]["checks"][
        "linux_serial_after_matches"
    ] is False
    assert "post_collection_inventory_error" in (
        evidence["identity"]["checks"]
    )


def test_collect_rejects_wrong_initial_device(
    monkeypatch, tmp_path
):
    configure_collector(
        monkeypatch,
        inventories=[make_inventory(serial="WRONG-SERIAL")],
    )
    output = tmp_path / "wrong-initial-device"

    with pytest.raises(RuntimeError, match="serial"):
        collector.collect(
            "/dev/sda",
            EXPECTED_SERIAL,
            output,
        )

    assert not output.exists()


def test_collect_rejects_existing_output_directory(
    monkeypatch, tmp_path
):
    configure_collector(monkeypatch)
    output = tmp_path / "existing-evidence"
    output.mkdir()

    with pytest.raises(RuntimeError, match="already exists"):
        collector.collect(
            "/dev/sda",
            EXPECTED_SERIAL,
            output,
        )


def test_collect_records_incomplete_status_on_command_exception(
    monkeypatch, tmp_path
):
    configure_collector(monkeypatch)
    call_count = 0

    def failing_run_command(argv, timeout=60):
        nonlocal call_count
        call_count += 1

        if call_count == 1:
            return make_record(
                argv,
                stdout=b"openSeaChest_Info version 26.03.2\n",
            )

        raise OSError("Simulated command execution failure")

    monkeypatch.setattr(
        collector,
        "run_command",
        failing_run_command,
    )

    output = tmp_path / "incomplete-command"
    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    evidence = read_manifest(output)
    assert_manifest_valid(evidence)
    assert_artifacts_valid(output, evidence)

    assert result == 1
    assert evidence["collection"]["status"] == "INCOMPLETE"
    assert evidence["capture"]["status"] == "PARTIAL"
    assert evidence["identity"]["status"] == "NOT_CHECKED"
    assert evidence["collection"]["error"]["type"] == "OSError"
    assert "Simulated command execution failure" in (
        evidence["collection"]["error"]["message"]
    )

    assert len(evidence["commands"]) == 1
    assert evidence["commands"][0]["name"] == "version"


def test_collect_records_incomplete_status_on_output_save_exception(
    monkeypatch, tmp_path
):
    configure_collector(monkeypatch)
    original_save = collector.save_command_output

    def failing_save(output_dir, name, record):
        if name == "device_info":
            raise OSError("Simulated evidence write failure")

        return original_save(output_dir, name, record)

    monkeypatch.setattr(
        collector,
        "save_command_output",
        failing_save,
    )

    output = tmp_path / "incomplete-save"
    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    evidence = read_manifest(output)
    assert_manifest_valid(evidence)
    assert_artifacts_valid(output, evidence)

    assert result == 1
    assert evidence["collection"]["status"] == "INCOMPLETE"
    assert evidence["capture"]["status"] == "PARTIAL"
    assert evidence["collection"]["error"]["type"] == "OSError"

    assert [
        command["name"] for command in evidence["commands"]
    ] == ["version", "usb_scan"]

    assert len(evidence["artifacts"]) == 4
