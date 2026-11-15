
import hashlib
import json
from pathlib import Path

import pytest

from collectors.openseachest.collector import (
    extract_ata_serial,
    save_command_output,
    validate_device,
)


EXPECTED_SERIAL = "TEST-SERIAL-0001"


def test_extract_ata_serial_uses_ata_section():
    output = b"""
SCSI Translator Reported Information:
    Serial Number: 0000000000000000

ATA Reported Information:
    Model Number: Samsung SSD 850 EVO 250GB
    Serial Number: TEST-SERIAL-0001
    Firmware Revision: EMT02B6Q
"""

    assert extract_ata_serial(output) == EXPECTED_SERIAL


def test_extract_ata_serial_returns_none_without_ata_section():
    output = b"""
SCSI Translator Reported Information:
    Serial Number: 0000000000000000
"""

    assert extract_ata_serial(output) is None


def test_extract_ata_serial_returns_none_if_serial_missing():
    output = b"""
ATA Reported Information:
    Model Number: Samsung SSD 850 EVO 250GB
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


def test_save_command_output_preserves_raw_bytes_and_hashes(tmp_path):
    stdout = b"\x00OSE evidence\xff\n"
    stderr = b"diagnostic output\n"

    record = {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": ["/usr/bin/example", "--version"],
        "exit_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": False,
    }

    metadata = save_command_output(tmp_path, "test", record)

    assert (tmp_path / "test.stdout.bin").read_bytes() == stdout
    assert (tmp_path / "test.stderr.bin").read_bytes() == stderr

    assert metadata["stdout_size_bytes"] == len(stdout)
    assert metadata["stderr_size_bytes"] == len(stderr)

    assert metadata["stdout_sha256"] == hashlib.sha256(stdout).hexdigest()
    assert metadata["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()

    assert metadata["successful"] is True


def test_save_command_output_marks_nonzero_exit_as_failure(tmp_path):
    record = {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": ["/usr/bin/example"],
        "exit_code": 2,
        "stdout": b"",
        "stderr": b"simulated failure",
        "timed_out": False,
    }

    metadata = save_command_output(tmp_path, "failure", record)

    assert metadata["successful"] is False
    assert (tmp_path / "failure.stderr.bin").read_bytes() == b"simulated failure"


def test_save_command_output_marks_timeout_as_failure(tmp_path):
    record = {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:10+00:00",
        "duration_seconds": 10.0,
        "argv": ["/usr/bin/example"],
        "exit_code": None,
        "stdout": b"partial output",
        "stderr": b"",
        "timed_out": True,
    }

    metadata = save_command_output(tmp_path, "timeout", record)

    assert metadata["successful"] is False
    assert (tmp_path / "timeout.stdout.bin").read_bytes() == b"partial output"
