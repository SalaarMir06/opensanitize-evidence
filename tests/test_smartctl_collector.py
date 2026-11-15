import hashlib

import pytest

from collectors.smartctl.collector import (
    decode_exit_status,
    extract_ata_serial,
    save_command_output,
    validate_device,
)


EXPECTED_SERIAL = "TEST-SERIAL-0001"


def test_decode_exit_status_zero():
    result = decode_exit_status(0)

    assert result["raw_exit_code"] == 0
    assert result["flags"] == []
    assert result["disk_failing"] is False


def test_decode_exit_status_disk_failing():
    result = decode_exit_status(8)

    assert result["raw_exit_code"] == 8
    assert result["disk_failing"] is True
    assert "disk_failing" in result["flags"]


def test_decode_exit_status_error_log_and_selftest_log():
    result = decode_exit_status(192)

    assert "error_log_records" in result["flags"]
    assert "selftest_log_records" in result["flags"]


def test_decode_exit_status_combined_flags():
    result = decode_exit_status(72)

    assert result["disk_failing"] is True
    assert "error_log_records" in result["flags"]
    assert len(result["flags"]) == 2


def test_decode_exit_status_rejects_invalid_values():
    with pytest.raises(ValueError):
        decode_exit_status(-1)

    with pytest.raises(ValueError):
        decode_exit_status(256)


def test_extract_ata_serial():
    output = b"""
smartctl 7.5
Device Model: Samsung SSD 850 EVO 250GB
Serial Number: TEST-SERIAL-0001
"""

    assert extract_ata_serial(output) == EXPECTED_SERIAL


def test_extract_ata_serial_returns_none_when_missing():
    output = b"""
smartctl 7.5
Device Model: Samsung SSD 850 EVO 250GB
"""

    assert extract_ata_serial(output) is None


def test_validate_device_accepts_expected_usb_disk():
    device = {
        "path": "/dev/sda",
        "type": "disk",
        "serial": EXPECTED_SERIAL,
        "tran": "usb",
    }

    validate_device(device, EXPECTED_SERIAL)


def test_validate_device_rejects_wrong_serial():
    device = {
        "path": "/dev/sda",
        "type": "disk",
        "serial": "WRONG-SERIAL",
        "tran": "usb",
    }

    with pytest.raises(RuntimeError, match="serial"):
        validate_device(device, EXPECTED_SERIAL)


def test_validate_device_rejects_non_usb_device():
    device = {
        "path": "/dev/sda",
        "type": "disk",
        "serial": EXPECTED_SERIAL,
        "tran": "sata",
    }

    with pytest.raises(RuntimeError, match="USB"):
        validate_device(device, EXPECTED_SERIAL)


def test_save_command_output_preserves_bytes_and_hashes(tmp_path):
    stdout = b"\x00SMART evidence\xff\n"
    stderr = b"diagnostic output\n"

    record = {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": ["/usr/sbin/smartctl", "--version"],
        "exit_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": False,
    }

    metadata = save_command_output(tmp_path, "test", record)

    assert (tmp_path / "test.stdout.bin").read_bytes() == stdout
    assert (tmp_path / "test.stderr.bin").read_bytes() == stderr
    assert metadata["stdout_sha256"] == hashlib.sha256(stdout).hexdigest()
    assert metadata["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()
    assert metadata["capture_complete"] is True
    assert metadata["exit_code_zero"] is True


def test_nonzero_smartctl_status_does_not_mean_capture_failed(tmp_path):
    record = {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": ["/usr/sbin/smartctl", "-x", "-d", "sat", "/dev/sda"],
        "exit_code": 64,
        "stdout": b"SMART data captured",
        "stderr": b"",
        "timed_out": False,
    }

    metadata = save_command_output(tmp_path, "smart_full", record)

    assert metadata["capture_complete"] is True
    assert metadata["exit_code_zero"] is False
    assert metadata["smartctl_status"]["flags"] == ["error_log_records"]


def test_save_command_output_marks_timeout_incomplete(tmp_path):
    record = {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:10+00:00",
        "duration_seconds": 10.0,
        "argv": ["/usr/sbin/smartctl", "-x", "-d", "sat", "/dev/sda"],
        "exit_code": None,
        "stdout": b"partial output",
        "stderr": b"",
        "timed_out": True,
    }

    metadata = save_command_output(tmp_path, "timeout", record)

    assert metadata["capture_complete"] is False
    assert metadata["exit_code_zero"] is False
    assert (tmp_path / "timeout.stdout.bin").read_bytes() == b"partial output"
