import hashlib

import pytest

from collectors.hdparm.collector import (
    extract_ata_serial,
    save_command_output,
    validate_device,
)


EXPECTED_SERIAL = "TEST-SERIAL-0001"


def test_extract_ata_serial():
    output = b"""
ATA device
Model Number: Samsung SSD 850 EVO 250GB
Serial Number: TEST-SERIAL-0001
Firmware Revision: EMT02B6Q
"""

    assert extract_ata_serial(output) == EXPECTED_SERIAL


def test_extract_ata_serial_returns_none_when_missing():
    assert extract_ata_serial(b"ATA device without serial") is None


def test_extract_ata_serial_handles_invalid_utf8():
    output = b"Serial Number: TEST-SERIAL-0001\xff\n"

    assert extract_ata_serial(output) == EXPECTED_SERIAL


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


def test_validate_device_rejects_partition():
    device = {
        "path": "/dev/sda1",
        "type": "part",
        "serial": EXPECTED_SERIAL,
        "tran": "usb",
    }

    with pytest.raises(RuntimeError, match="whole disk"):
        validate_device(device, EXPECTED_SERIAL)


def test_save_command_output_preserves_raw_bytes_and_hashes(tmp_path):
    stdout = b"\x00ATA evidence\xff\n"
    stderr = b"diagnostic output\n"

    record = {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": ["/usr/sbin/hdparm", "-I", "/dev/sda"],
        "exit_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": False,
    }

    metadata = save_command_output(tmp_path, "identify", record)

    assert (tmp_path / "identify.stdout.bin").read_bytes() == stdout
    assert (tmp_path / "identify.stderr.bin").read_bytes() == stderr
    assert metadata["stdout_sha256"] == hashlib.sha256(stdout).hexdigest()
    assert metadata["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()
    assert metadata["stdout_size_bytes"] == len(stdout)
    assert metadata["stderr_size_bytes"] == len(stderr)
    assert metadata["capture_complete"] is True
    assert metadata["exit_code_zero"] is True


def test_save_command_output_marks_nonzero_exit(tmp_path):
    record = {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": ["/usr/sbin/hdparm", "-I", "/dev/sda"],
        "exit_code": 1,
        "stdout": b"partial identify output",
        "stderr": b"command error",
        "timed_out": False,
    }

    metadata = save_command_output(tmp_path, "identify", record)

    assert metadata["capture_complete"] is True
    assert metadata["exit_code_zero"] is False


def test_save_command_output_marks_timeout_incomplete(tmp_path):
    record = {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:10+00:00",
        "duration_seconds": 10.0,
        "argv": ["/usr/sbin/hdparm", "-I", "/dev/sda"],
        "exit_code": None,
        "stdout": b"partial identify output",
        "stderr": b"",
        "timed_out": True,
    }

    metadata = save_command_output(tmp_path, "timeout", record)

    assert metadata["capture_complete"] is False
    assert metadata["exit_code_zero"] is False
    assert (tmp_path / "timeout.stdout.bin").read_bytes() == (
        b"partial identify output"
    )
