
import json

import pytest

from collectors.openseachest import collector


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


def make_record(argv, stdout=b"OK\n", stderr=b"", exit_code=0,
                timed_out=False):
    return {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": argv,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
    }


def configure_collector(monkeypatch, inventories=None, failures=None,
                        sat_output=SAT_OUTPUT, scan_output=SCAN_OUTPUT):
    monkeypatch.setattr(
        collector.shutil,
        "which",
        lambda name: {
            "openSeaChest_Info": "/usr/local/bin/openSeaChest_Info",
            "sudo": "/usr/bin/sudo",
        }.get(name),
    )

    inventory_results = list(
        inventories or [
            make_inventory(),
            make_inventory(),
        ]
    )

    def fake_inventory(device):
        return inventory_results.pop(0)

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


def test_collect_success(monkeypatch, tmp_path):
    configure_collector(monkeypatch)

    output = tmp_path / "successful-collection"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    assert result == 0

    evidence = json.loads(
        (output / "collection.json").read_text()
    )

    assert evidence["collection_status"] == "SUCCESS"
    assert evidence["identity_checks"]["ata_serial_matches"] is True
    assert evidence["identity_checks"][
        "linux_serial_after_matches"
    ] is True
    assert evidence["identity_checks"][
        "usb_scan_contains_expected_serial"
    ] is True

    assert len(evidence["commands"]) == 4

    for command in evidence["commands"].values():
        assert command["successful"] is True

    assert (output / "sat_info.stdout.bin").read_bytes() == SAT_OUTPUT


def test_collect_fails_when_command_returns_nonzero(
    monkeypatch, tmp_path
):
    configure_collector(
        monkeypatch,
        failures={"device_info": "nonzero"},
    )

    output = tmp_path / "failed-command"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    assert result == 1

    evidence = json.loads(
        (output / "collection.json").read_text()
    )

    assert evidence["collection_status"] == "FAILED"
    assert evidence["commands"]["device_info"]["successful"] is False

    # Evidence from all commands must still be retained.
    assert (output / "device_info.stderr.bin").read_bytes() == (
        b"Simulated command failure"
    )


def test_collect_fails_when_ata_serial_does_not_match(
    monkeypatch, tmp_path
):
    wrong_sat_output = SAT_OUTPUT.replace(
        EXPECTED_SERIAL.encode(),
        b"WRONG-SERIAL",
    )

    configure_collector(
        monkeypatch,
        sat_output=wrong_sat_output,
    )

    output = tmp_path / "wrong-ata-identity"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    assert result == 1

    evidence = json.loads(
        (output / "collection.json").read_text()
    )

    assert evidence["collection_status"] == "FAILED"
    assert evidence["identity_checks"]["ata_serial_matches"] is False


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

    assert result == 1

    evidence = json.loads(
        (output / "collection.json").read_text()
    )

    assert evidence["collection_status"] == "FAILED"
    assert evidence["identity_checks"][
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

    assert result == 1

    evidence = json.loads(
        (output / "collection.json").read_text()
    )

    assert evidence["collection_status"] == "FAILED"
    assert evidence["identity_checks"][
        "linux_serial_after_matches"
    ] is False


def test_collect_rejects_wrong_initial_device(
    monkeypatch, tmp_path
):
    configure_collector(
        monkeypatch,
        inventories=[
            make_inventory(serial="WRONG-SERIAL"),
        ],
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

    assert result == 1

    evidence = json.loads(
        (output / "collection.json").read_text()
    )

    assert evidence["collection_status"] == "INCOMPLETE"
    assert evidence["collection_error"]["type"] == "OSError"
    assert "Simulated command execution failure" in (
        evidence["collection_error"]["message"]
    )

    # The completed version command must remain recorded.
    assert "version" in evidence["commands"]
    assert (output / "version.stdout.bin").read_bytes() == (
        b"openSeaChest_Info version 26.03.2\n"
    )


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

    assert result == 1

    evidence = json.loads(
        (output / "collection.json").read_text()
    )

    assert evidence["collection_status"] == "INCOMPLETE"
    assert evidence["collection_error"]["type"] == "OSError"
    assert "Simulated evidence write failure" in (
        evidence["collection_error"]["message"]
    )

    # Earlier completed command evidence must remain intact.
    assert "version" in evidence["commands"]
    assert "usb_scan" in evidence["commands"]
    assert "device_info" not in evidence["commands"]

    assert (output / "version.stdout.bin").exists()
    assert (output / "usb_scan.stdout.bin").exists()
