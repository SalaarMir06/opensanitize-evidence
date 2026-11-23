import json

import pytest

from collectors.hdparm import collector


EXPECTED_SERIAL = "TEST-SERIAL-0001"

DEVICE = {
    "path": "/dev/sda",
    "type": "disk",
    "size": 250059350016,
    "model": "Samsung SSD 850 EVO 250GB",
    "serial": EXPECTED_SERIAL,
    "tran": "usb",
}


def make_record(argv, stdout=b"", stderr=b"", exit_code=0, timed_out=False):
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


def setup_collector(monkeypatch, run_command):
    monkeypatch.setattr(
        collector.shutil,
        "which",
        lambda name: {
            "hdparm": "/usr/sbin/hdparm",
            "sudo": "/usr/bin/sudo",
        }.get(name),
    )
    monkeypatch.setattr(
        collector,
        "get_device_inventory",
        lambda device, serial: DEVICE.copy(),
    )
    monkeypatch.setattr(collector, "run_command", run_command)


def test_collect_success(monkeypatch, tmp_path):
    calls = []

    def fake_run_command(argv, timeout=60):
        calls.append(argv)

        if argv == ["/usr/sbin/hdparm", "-V"]:
            return make_record(argv, stdout=b"hdparm v9.65\n")

        if argv == [
            "/usr/bin/sudo", "-n", "/usr/sbin/hdparm",
            "-I", "/dev/sda",
        ]:
            return make_record(
                argv,
                stdout=(
                    b"ATA device\n"
                    b"Serial Number: TEST-SERIAL-0001\n"
                ),
            )

        pytest.fail(f"Unexpected command: {argv}")

    setup_collector(monkeypatch, fake_run_command)

    output = tmp_path / "hdparm-evidence"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    assert result == 0
    assert len(calls) == 2

    manifest = json.loads(
        (output / "collection.json").read_text()
    )

    assert manifest["collection_status"] == "SUCCESS"
    assert manifest["capture_complete"] is True
    assert manifest["commands_successful"] is True
    assert manifest["identity_successful"] is True
    assert manifest["identity_checks"]["hdparm_identify_serial_matches"]
    assert manifest["safety"]["read_only_collection"] is True
    assert manifest["safety"]["destructive_commands_executed"] is False

    assert calls == [
        ["/usr/sbin/hdparm", "-V"],
        [
            "/usr/bin/sudo", "-n", "/usr/sbin/hdparm",
            "-I", "/dev/sda",
        ],
    ]


def test_nonzero_exit_preserves_capture_but_fails_collection(
    monkeypatch, tmp_path
):
    def fake_run_command(argv, timeout=60):
        if argv[-1] == "-V":
            return make_record(
                argv,
                stdout=b"hdparm v9.65\n",
            )

        return make_record(
            argv,
            stdout=b"Serial Number: TEST-SERIAL-0001\n",
            stderr=b"hdparm warning\n",
            exit_code=1,
        )

    setup_collector(monkeypatch, fake_run_command)

    output = tmp_path / "hdparm-nonzero"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    manifest = json.loads(
        (output / "collection.json").read_text()
    )

    assert result == 1
    assert manifest["capture_complete"] is True
    assert manifest["commands_successful"] is False
    assert manifest["identity_successful"] is True
    assert manifest["collection_status"] == "FAILED"
    assert (
        output / "identify.stderr.bin"
    ).read_bytes() == b"hdparm warning\n"


def test_collect_fails_when_identify_serial_does_not_match(
    monkeypatch, tmp_path
):
    def fake_run_command(argv, timeout=60):
        if argv[-1] == "-V":
            return make_record(argv, stdout=b"hdparm v9.65\n")

        return make_record(
            argv,
            stdout=b"Serial Number: WRONG-SERIAL\n",
        )

    setup_collector(monkeypatch, fake_run_command)

    output = tmp_path / "hdparm-wrong-serial"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    manifest = json.loads(
        (output / "collection.json").read_text()
    )

    assert result == 1
    assert manifest["capture_complete"] is True
    assert manifest["identity_successful"] is False
    assert manifest["collection_status"] == "FAILED"


def test_collect_fails_when_command_times_out(
    monkeypatch, tmp_path
):
    def fake_run_command(argv, timeout=60):
        if argv[-1] == "-V":
            return make_record(argv, stdout=b"hdparm v9.65\n")

        return make_record(
            argv,
            stdout=b"Serial Number: TEST-SERIAL-0001\n",
            exit_code=None,
            timed_out=True,
        )

    setup_collector(monkeypatch, fake_run_command)

    output = tmp_path / "hdparm-timeout"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    manifest = json.loads(
        (output / "collection.json").read_text()
    )

    assert result == 1
    assert manifest["capture_complete"] is False
    assert manifest["collection_status"] == "FAILED"
    assert manifest["commands"]["identify"]["timed_out"] is True


def test_invalid_initial_device_prevents_commands(
    monkeypatch, tmp_path
):
    def unexpected_command(*args, **kwargs):
        pytest.fail("No hdparm command should execute")

    monkeypatch.setattr(
        collector.shutil,
        "which",
        lambda name: "/usr/sbin/hdparm" if name == "hdparm"
        else "/usr/bin/sudo",
    )
    monkeypatch.setattr(
        collector,
        "get_device_inventory",
        lambda device, serial: (_ for _ in ()).throw(
            RuntimeError("Selected device is not USB-connected")
        ),
    )
    monkeypatch.setattr(
        collector,
        "run_command",
        unexpected_command,
    )

    output = tmp_path / "hdparm-invalid-device"

    with pytest.raises(RuntimeError, match="USB"):
        collector.collect(
            "/dev/sda",
            EXPECTED_SERIAL,
            output,
        )

    assert not output.exists()


def test_existing_output_directory_is_rejected(
    monkeypatch, tmp_path
):
    output = tmp_path / "existing"
    output.mkdir()

    with pytest.raises(RuntimeError, match="already exists"):
        collector.collect(
            "/dev/sda",
            EXPECTED_SERIAL,
            output,
        )


def test_command_exception_writes_incomplete_manifest(
    monkeypatch, tmp_path
):
    def failing_command(argv, timeout=60):
        raise OSError("simulated command execution failure")

    setup_collector(monkeypatch, failing_command)

    output = tmp_path / "hdparm-incomplete"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    manifest = json.loads(
        (output / "collection.json").read_text()
    )

    assert result == 1
    assert manifest["collection_status"] == "INCOMPLETE"
    assert manifest["capture_complete"] is False
    assert manifest["collection_error"]["type"] == "OSError"
    assert manifest["safety"]["destructive_commands_executed"] is False
