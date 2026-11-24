import json
from pathlib import Path

import pytest

from collectors.smartctl import collector


EXPECTED_SERIAL = "TEST-SERIAL-0001"
DEVICE = "/dev/sda"


def make_inventory():
    return {
        "path": DEVICE,
        "type": "disk",
        "size": "250059350016",
        "model": "Samsung SSD 850 EVO 250GB",
        "serial": EXPECTED_SERIAL,
        "tran": "usb",
    }


def make_record(stdout=b"", exit_code=0, timed_out=False):
    return {
        "started_utc": "2026-11-15T10:00:00+00:00",
        "finished_utc": "2026-11-15T10:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": ["mocked-command"],
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": b"",
        "timed_out": timed_out,
    }


def smartctl_report(serial=EXPECTED_SERIAL):
    return (
        "Device Model: Samsung SSD 850 EVO 250GB\n"
        f"Serial Number: {serial}\n"
        "Firmware Version: EMT02B6Q\n"
    ).encode()


def configure_mocks(monkeypatch, run_side_effect=None):
    monkeypatch.setattr(
        collector.shutil,
        "which",
        lambda name: {
            "smartctl": "/usr/sbin/smartctl",
            "sudo": "/usr/bin/sudo",
        }.get(name),
    )

    inventory_calls = []

    def fake_inventory(device, expected_serial):
        inventory_calls.append((device, expected_serial))
        return make_inventory()

    monkeypatch.setattr(
        collector,
        "get_device_inventory",
        fake_inventory,
    )

    calls = []

    def fake_run_command(argv, timeout=60):
        calls.append(argv)

        if run_side_effect:
            return run_side_effect(argv)

        if "--version" in argv:
            return make_record(b"smartctl 7.5\n")

        if "--scan-open" in argv:
            return make_record(b"/dev/sda -d sat\n")

        if "-i" in argv:
            return make_record(smartctl_report())

        if "-x" in argv:
            return make_record(smartctl_report())

        pytest.fail(f"Unexpected command: {argv}")

    monkeypatch.setattr(collector, "run_command", fake_run_command)

    return calls, inventory_calls


def test_collect_success(tmp_path, monkeypatch):
    calls, inventory_calls = configure_mocks(monkeypatch)
    output = tmp_path / "smartctl-evidence"

    result = collector.collect(DEVICE, EXPECTED_SERIAL, output)

    assert result == 0
    assert len(calls) == 4
    assert len(inventory_calls) == 2

    manifest = json.loads((output / "collection.json").read_text())

    assert manifest["schema_version"] == "2.0"
    assert manifest["collection"]["status"] == "COMPLETE"
    assert manifest["capture"]["status"] == "COMPLETE"
    assert manifest["identity"]["status"] == "VERIFIED"
    assert manifest["target"]["expected_identity"]["serial"] == EXPECTED_SERIAL
    assert manifest["safety"]["read_only_collection"] is True
    assert manifest["safety"]["destructive_commands_executed"] is False
    assert manifest["assessment"]["status"] == "NOT_ASSESSED"
    assert collector.validate_manifest(manifest) == []

    assert len(manifest["commands"]) == 4
    assert len(manifest["artifacts"]) == 8

    full_report = next(
        item for item in manifest["commands"]
        if item["name"] == "device_full"
    )
    assert full_report["execution_status"] == "COMPLETED"
    assert len(full_report["artifact_ids"]) == 2

    assert (output / "version.stdout.bin").read_bytes() == b"smartctl 7.5\n"

    command_text = [" ".join(argv) for argv in calls]
    assert any("--version" in cmd for cmd in command_text)
    assert any("--scan-open" in cmd for cmd in command_text)
    assert any("-i -d sat" in cmd for cmd in command_text)
    assert any("-x -d sat" in cmd for cmd in command_text)

    for command in command_text:
        assert "erase" not in command.lower()
        assert "sanitize" not in command.lower()
        assert "self-test" not in command.lower()


def test_nonzero_smartctl_status_preserves_complete_capture(
    tmp_path, monkeypatch
):
    def simulated_command(argv):
        if "-x" in argv:
            return make_record(smartctl_report(), exit_code=64)
        if "--version" in argv:
            return make_record(b"smartctl 7.5\n")
        if "--scan-open" in argv:
            return make_record(b"/dev/sda -d sat\n")
        if "-i" in argv:
            return make_record(smartctl_report())
        pytest.fail(f"Unexpected command: {argv}")

    configure_mocks(monkeypatch, simulated_command)
    output = tmp_path / "smartctl-nonzero-status"

    result = collector.collect(DEVICE, EXPECTED_SERIAL, output)

    assert result == 0

    manifest = json.loads((output / "collection.json").read_text())
    assert manifest["schema_version"] == "2.0"
    assert collector.validate_manifest(manifest) == []

    full_report = next(
        item for item in manifest["commands"]
        if item["name"] == "device_full"
    )

    assert full_report["exit_code"] == 64
    assert full_report["execution_status"] == "COMPLETED"
    assert full_report["extensions"]["exit_code_zero"] is False
    assert full_report["extensions"]["smartctl_status"]["flags"] == [
        "error_log_records"
    ]
    assert manifest["collection"]["status"] == "COMPLETE"
    assert manifest["capture"]["status"] == "COMPLETE"
    assert manifest["identity"]["status"] == "VERIFIED"


def test_collect_fails_when_smartctl_serial_does_not_match(
    tmp_path, monkeypatch
):
    def simulated_command(argv):
        if "--version" in argv:
            return make_record(b"smartctl 7.5\n")
        if "--scan-open" in argv:
            return make_record(b"/dev/sda -d sat\n")
        if "-i" in argv or "-x" in argv:
            return make_record(smartctl_report("WRONG-SERIAL"))
        pytest.fail(f"Unexpected command: {argv}")

    configure_mocks(monkeypatch, simulated_command)
    output = tmp_path / "smartctl-wrong-serial"

    result = collector.collect(DEVICE, EXPECTED_SERIAL, output)

    assert result == 1

    manifest = json.loads((output / "collection.json").read_text())
    assert manifest["schema_version"] == "2.0"
    assert collector.validate_manifest(manifest) == []

    assert manifest["collection"]["status"] == "COMPLETE"
    assert manifest["capture"]["status"] == "COMPLETE"
    assert manifest["identity"]["status"] == "FAILED"
    assert manifest["identity"]["checks"]["smartctl_info_serial_matches"] is False
    assert manifest["identity"]["checks"]["smartctl_full_report_serial_matches"] is False


def test_collect_fails_when_command_times_out(tmp_path, monkeypatch):
    def simulated_command(argv):
        if "--version" in argv:
            return make_record(b"smartctl 7.5\n")
        if "--scan-open" in argv:
            return make_record(b"/dev/sda -d sat\n")
        if "-i" in argv:
            return make_record(smartctl_report())
        if "-x" in argv:
            return make_record(
                stdout=smartctl_report(),
                exit_code=None,
                timed_out=True,
            )
        pytest.fail(f"Unexpected command: {argv}")

    configure_mocks(monkeypatch, simulated_command)
    output = tmp_path / "smartctl-timeout"

    result = collector.collect(DEVICE, EXPECTED_SERIAL, output)

    assert result == 1

    manifest = json.loads((output / "collection.json").read_text())
    assert manifest["schema_version"] == "2.0"
    assert collector.validate_manifest(manifest) == []

    full_report = next(
        item for item in manifest["commands"]
        if item["name"] == "device_full"
    )

    assert full_report["timed_out"] is True
    assert full_report["execution_status"] == "TIMED_OUT"
    assert full_report["exit_code"] is None

    stdout_artifact = next(
        artifact for artifact in manifest["artifacts"]
        if artifact["path"] == "device_full.stdout.bin"
    )
    assert stdout_artifact["role"] == "stdout"

    assert (output / "device_full.stdout.bin").read_bytes() == smartctl_report()

    assert manifest["capture"]["status"] == "PARTIAL"
    assert manifest["collection"]["status"] == "INCOMPLETE"
    assert manifest["identity"]["status"] == "NOT_CHECKED"
    assert manifest["identity"]["checks"] == {}


def test_invalid_initial_device_prevents_command_execution(
    tmp_path, monkeypatch
):
    calls = []

    monkeypatch.setattr(
        collector.shutil,
        "which",
        lambda name: {
            "smartctl": "/usr/sbin/smartctl",
            "sudo": "/usr/bin/sudo",
        }.get(name),
    )

    def reject_device(device, expected_serial):
        raise RuntimeError("Linux device serial does not match expected serial")

    monkeypatch.setattr(
        collector,
        "get_device_inventory",
        reject_device,
    )

    def unexpected_command(argv, timeout=60):
        calls.append(argv)
        pytest.fail("No commands should run after identity validation fails")

    monkeypatch.setattr(
        collector,
        "run_command",
        unexpected_command,
    )

    output = tmp_path / "smartctl-invalid-device"

    with pytest.raises(RuntimeError, match="serial does not match"):
        collector.collect(
            DEVICE,
            EXPECTED_SERIAL,
            output,
        )

    assert calls == []
    assert not output.exists()



def test_collect_records_command_when_output_save_fails(
    tmp_path, monkeypatch
):
    configure_mocks(monkeypatch)
    original_save = collector.save_command_output

    def failing_save(output_dir, name, record):
        if name == "device_full":
            raise OSError("simulated smartctl evidence write failure")
        return original_save(output_dir, name, record)

    monkeypatch.setattr(
        collector,
        "save_command_output",
        failing_save,
    )

    output = tmp_path / "smartctl-save-failure"
    result = collector.collect(DEVICE, EXPECTED_SERIAL, output)

    manifest = json.loads((output / "collection.json").read_text())
    assert collector.validate_manifest(manifest) == []

    assert result == 1
    assert manifest["collection"]["status"] == "INCOMPLETE"
    assert manifest["capture"]["status"] == "PARTIAL"
    assert manifest["identity"]["status"] == "NOT_CHECKED"
    assert manifest["collection"]["error"]["type"] == "OSError"

    failed_command = manifest["commands"][-1]
    assert failed_command["name"] == "device_full"
    assert failed_command["execution_status"] == "COMPLETED"
    assert failed_command["exit_code"] == 0
    assert failed_command["artifact_ids"] == []

    assert len(manifest["commands"]) == 4
    assert len(manifest["artifacts"]) == 6
    assert all(
        (output / artifact["path"]).is_file()
        for artifact in manifest["artifacts"]
    )

def test_identity_verified_when_unrelated_version_command_times_out(
    tmp_path, monkeypatch
):
    def simulated_command(argv):
        if "--version" in argv:
            return make_record(
                stdout=b"Partial version output",
                exit_code=None,
                timed_out=True,
            )
        if "--scan-open" in argv:
            return make_record(b"/dev/sda -d sat\\n")
        if "-i" in argv or "-x" in argv:
            return make_record(smartctl_report())
        pytest.fail(f"Unexpected command: {argv}")

    configure_mocks(monkeypatch, simulated_command)
    output = tmp_path / "smartctl-version-timeout"

    result = collector.collect(DEVICE, EXPECTED_SERIAL, output)

    manifest = json.loads((output / "collection.json").read_text())
    assert collector.validate_manifest(manifest) == []

    assert result == 1
    assert manifest["collection"]["status"] == "INCOMPLETE"
    assert manifest["capture"]["status"] == "PARTIAL"
    assert manifest["identity"]["status"] == "VERIFIED"
