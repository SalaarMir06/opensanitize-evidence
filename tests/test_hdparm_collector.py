import hashlib

import pytest

from collectors.hdparm.collector import (
    build_command_record,
    extract_ata_serial,
    save_command_output,
    validate_device,
)


EXPECTED_SERIAL = "TEST-SERIAL-0001"


def make_record(
    stdout=b"",
    stderr=b"",
    exit_code=0,
    timed_out=False,
):
    return {
        "started_utc": "2026-11-15T08:00:00+00:00",
        "finished_utc": "2026-11-15T08:00:01+00:00",
        "duration_seconds": 1.0,
        "argv": ["/usr/sbin/hdparm", "-I", "/dev/sda"],
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
    }


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


def test_validate_device_accepts_case_insensitive_usb_transport():
    device = {
        "path": "/dev/sda",
        "type": "disk",
        "serial": EXPECTED_SERIAL,
        "tran": "USB",
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

    artifacts = save_command_output(
        tmp_path,
        "identify",
        make_record(stdout=stdout, stderr=stderr),
    )

    assert (tmp_path / "identify.stdout.bin").read_bytes() == stdout
    assert (tmp_path / "identify.stderr.bin").read_bytes() == stderr

    assert len(artifacts) == 2

    stdout_artifact = artifacts[0]
    stderr_artifact = artifacts[1]

    assert stdout_artifact["artifact_id"] == "identify-stdout"
    assert stdout_artifact["role"] == "stdout"
    assert stdout_artifact["path"] == "identify.stdout.bin"
    assert stdout_artifact["size_bytes"] == len(stdout)
    assert stdout_artifact["hash"]["algorithm"] == "sha256"
    assert stdout_artifact["hash"]["value"] == (
        hashlib.sha256(stdout).hexdigest()
    )

    assert stderr_artifact["artifact_id"] == "identify-stderr"
    assert stderr_artifact["role"] == "stderr"
    assert stderr_artifact["path"] == "identify.stderr.bin"
    assert stderr_artifact["size_bytes"] == len(stderr)
    assert stderr_artifact["hash"]["value"] == (
        hashlib.sha256(stderr).hexdigest()
    )


def test_save_command_output_preserves_empty_streams(tmp_path):
    artifacts = save_command_output(
        tmp_path,
        "version",
        make_record(),
    )

    assert len(artifacts) == 2
    assert (tmp_path / "version.stdout.bin").read_bytes() == b""
    assert (tmp_path / "version.stderr.bin").read_bytes() == b""

    assert all(item["size_bytes"] == 0 for item in artifacts)
    assert all(
        item["hash"]["value"] == hashlib.sha256(b"").hexdigest()
        for item in artifacts
    )


def test_save_command_output_preserves_nonzero_exit_capture(tmp_path):
    artifacts = save_command_output(
        tmp_path,
        "identify",
        make_record(
            stdout=b"partial identify output",
            stderr=b"command error",
            exit_code=1,
        ),
    )

    assert len(artifacts) == 2
    assert (tmp_path / "identify.stdout.bin").read_bytes() == (
        b"partial identify output"
    )
    assert (tmp_path / "identify.stderr.bin").read_bytes() == (
        b"command error"
    )


def test_save_command_output_preserves_timeout_output(tmp_path):
    artifacts = save_command_output(
        tmp_path,
        "identify",
        make_record(
            stdout=b"partial identify output",
            timed_out=True,
            exit_code=None,
        ),
    )

    assert len(artifacts) == 2
    assert (tmp_path / "identify.stdout.bin").read_bytes() == (
        b"partial identify output"
    )


def test_build_command_record_marks_completed_nonzero_exit():
    record = make_record(exit_code=1)
    artifacts = [
        {"artifact_id": "identify-stdout"},
        {"artifact_id": "identify-stderr"},
    ]

    command = build_command_record(
        "identify",
        record,
        artifacts,
    )

    assert command["execution_status"] == "COMPLETED"
    assert command["timed_out"] is False
    assert command["exit_code"] == 1
    assert command["extensions"]["exit_code_zero"] is False
    assert command["artifact_ids"] == [
        "identify-stdout",
        "identify-stderr",
    ]


def test_build_command_record_marks_timeout():
    record = make_record(exit_code=None, timed_out=True)
    command = build_command_record("identify", record, [])

    assert command["execution_status"] == "TIMED_OUT"
    assert command["timed_out"] is True
    assert command["exit_code"] is None
    assert command["extensions"]["exit_code_zero"] is False
