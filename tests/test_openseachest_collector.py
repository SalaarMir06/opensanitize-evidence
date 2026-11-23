import hashlib
import pytest

from collectors.openseachest.collector import (
    extract_ata_serial,
    save_command_output,
    validate_device,
    validate_output_artifacts,
)


EXPECTED_SERIAL = "TEST-SERIAL-0001"


def test_extract_ata_serial_uses_ata_section():
    output = (
        b"SCSI Translator Reported Information:\n"
        b"Serial Number: 0000000000000000\n"
        b"\nATA Reported Information:\n"
        b"Model Number: Samsung SSD 850 EVO 250GB\n"
        b"Serial Number: TEST-SERIAL-0001\n"
    )

    assert extract_ata_serial(output) == EXPECTED_SERIAL


def test_extract_ata_serial_returns_none_without_ata_section():
    assert extract_ata_serial(
        b"SCSI Translator Reported Information:\n"
        b"Serial Number: 0000000000000000\n"
    ) is None


def test_extract_ata_serial_returns_none_if_missing():
    assert extract_ata_serial(
        b"ATA Reported Information:\n"
        b"Model Number: Samsung SSD 850 EVO 250GB\n"
    ) is None


def test_validate_device_accepts_expected_usb_disk():
    validate_device(
        {
            "path": "/dev/sda",
            "type": "disk",
            "serial": EXPECTED_SERIAL,
            "tran": "usb",
        },
        EXPECTED_SERIAL,
    )


def test_validate_device_rejects_wrong_serial():
    import pytest

    with pytest.raises(RuntimeError, match="serial"):
        validate_device(
            {
                "path": "/dev/sda",
                "type": "disk",
                "serial": "WRONG-SERIAL",
                "tran": "usb",
            },
            EXPECTED_SERIAL,
        )


def test_validate_device_rejects_non_usb_device():
    import pytest

    with pytest.raises(RuntimeError, match="USB"):
        validate_device(
            {
                "path": "/dev/sda",
                "type": "disk",
                "serial": EXPECTED_SERIAL,
                "tran": "sata",
            },
            EXPECTED_SERIAL,
        )


def test_save_command_output_preserves_raw_bytes_and_hashes(tmp_path):
    stdout = b"\x00OSE evidence\xff\n"
    stderr = b"diagnostic output\n"

    artifacts = save_command_output(
        tmp_path,
        "test",
        {
            "stdout": stdout,
            "stderr": stderr,
        },
    )

    assert len(artifacts) == 2

    for artifact, role, data in zip(
        artifacts,
        ("stdout", "stderr"),
        (stdout, stderr),
    ):
        assert artifact["role"] == role
        assert artifact["size_bytes"] == len(data)
        assert artifact["hash"]["algorithm"] == "sha256"
        assert artifact["hash"]["value"] == (
            hashlib.sha256(data).hexdigest()
        )
        assert (
            tmp_path / artifact["path"]
        ).read_bytes() == data


def test_save_command_output_handles_empty_streams(tmp_path):
    artifacts = save_command_output(
        tmp_path,
        "empty",
        {
            "stdout": b"",
            "stderr": b"",
        },
    )

    assert len(artifacts) == 2

    for artifact in artifacts:
        assert artifact["size_bytes"] == 0
        assert artifact["hash"]["value"] == (
            hashlib.sha256(b"").hexdigest()
        )
        assert (tmp_path / artifact["path"]).read_bytes() == b""


def test_save_command_output_rolls_back_if_second_stream_write_fails(
    monkeypatch, tmp_path
):
    path_type = type(tmp_path)
    original_write_bytes = path_type.write_bytes
    calls = 0

    def failing_second_write(self, data):
        nonlocal calls
        calls += 1

        if calls == 2:
            raise OSError("Simulated stderr write failure")

        return original_write_bytes(self, data)

    monkeypatch.setattr(
        path_type,
        "write_bytes",
        failing_second_write,
    )

    with pytest.raises(
        OSError,
        match="Simulated stderr write failure",
    ):
        save_command_output(
            tmp_path,
            "partial",
            {
                "stdout": b"captured stdout",
                "stderr": b"captured stderr",
            },
        )

    assert calls == 2
    assert list(tmp_path.iterdir()) == []


def test_validate_output_artifacts_rejects_unlisted_file(tmp_path):
    (tmp_path / "unexpected.bin").write_bytes(b"unlisted")

    with pytest.raises(ValueError, match="unexpected"):
        validate_output_artifacts(tmp_path, [])



def test_validate_output_artifacts_rejects_unlisted_directory(tmp_path):
    (tmp_path / "unexpected").mkdir()

    with pytest.raises(ValueError, match="unlisted directories"):
        validate_output_artifacts(tmp_path, [])


def test_validate_output_artifacts_rejects_modified_artifact(tmp_path):
    data = b"original evidence"
    (tmp_path / "evidence.bin").write_bytes(b"modified evidence")

    artifact = {
        "path": "evidence.bin",
        "size_bytes": len(data),
        "hash": {
            "algorithm": "sha256",
            "value": hashlib.sha256(data).hexdigest(),
        },
    }

    with pytest.raises(ValueError, match="size mismatch|SHA-256 mismatch"):
        validate_output_artifacts(tmp_path, [artifact])



def test_validate_output_artifacts_rejects_symlink_parent(tmp_path):
    real_directory = tmp_path / "real"
    real_directory.mkdir()

    data = b"evidence"
    (real_directory / "evidence.bin").write_bytes(data)

    link = tmp_path / "linked"
    link.symlink_to(real_directory, target_is_directory=True)

    artifact = {
        "path": "linked/evidence.bin",
        "size_bytes": len(data),
        "hash": {
            "algorithm": "sha256",
            "value": hashlib.sha256(data).hexdigest(),
        },
    }

    with pytest.raises(ValueError, match="Symlink"):
        validate_output_artifacts(tmp_path, [artifact])

def test_validate_output_artifacts_rejects_symlink(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"evidence")

    link = tmp_path / "linked.bin"
    link.symlink_to(target)

    artifact = {
        "path": "linked.bin",
        "size_bytes": len(b"evidence"),
        "hash": {
            "algorithm": "sha256",
            "value": hashlib.sha256(b"evidence").hexdigest(),
        },
    }

    with pytest.raises(ValueError, match="Symlink"):
        validate_output_artifacts(tmp_path, [artifact])
