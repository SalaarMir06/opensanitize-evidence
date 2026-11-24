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


def make_record(
    argv,
    stdout=b"",
    stderr=b"",
    exit_code=0,
    timed_out=False,
):
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


def read_manifest(output):
    manifest = json.loads(
        (output / "collection.json").read_text()
    )

    assert manifest["schema_version"] == "2.0"
    assert collector.validate_manifest(manifest) == []

    return manifest


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

    manifest = read_manifest(output)

    assert manifest["collection"]["status"] == "COMPLETE"
    assert manifest["capture"]["status"] == "COMPLETE"
    assert manifest["identity"]["status"] == "VERIFIED"
    assert manifest["target"]["expected_identity"]["serial"] == (
        EXPECTED_SERIAL
    )
    assert manifest["safety"]["read_only_collection"] is True
    assert manifest["safety"]["destructive_commands_executed"] is False
    assert manifest["assessment"]["status"] == "NOT_ASSESSED"

    assert len(manifest["commands"]) == 2
    assert len(manifest["artifacts"]) == 4

    assert [
        command["name"] for command in manifest["commands"]
    ] == ["version", "identify"]

    identify = manifest["commands"][1]

    assert identify["execution_status"] == "COMPLETED"
    assert identify["exit_code"] == 0
    assert len(identify["artifact_ids"]) == 2

    assert (
        output / "version.stdout.bin"
    ).read_bytes() == b"hdparm v9.65\n"

    assert calls == [
        ["/usr/sbin/hdparm", "-V"],
        [
            "/usr/bin/sudo", "-n", "/usr/sbin/hdparm",
            "-I", "/dev/sda",
        ],
    ]

    for argv in calls:
        command_text = " ".join(argv).lower()
        assert "erase" not in command_text
        assert "sanitize" not in command_text
        assert "security-set" not in command_text


def test_nonzero_exit_preserves_complete_capture(
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

    manifest = read_manifest(output)
    identify = manifest["commands"][1]

    assert result == 1
    assert identify["exit_code"] == 1
    assert identify["execution_status"] == "COMPLETED"
    assert identify["extensions"]["exit_code_zero"] is False

    assert manifest["collection"]["status"] == "COMPLETE"
    assert manifest["capture"]["status"] == "COMPLETE"
    assert manifest["identity"]["status"] == "VERIFIED"

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

    manifest = read_manifest(output)

    assert result == 1
    assert manifest["collection"]["status"] == "COMPLETE"
    assert manifest["capture"]["status"] == "COMPLETE"
    assert manifest["identity"]["status"] == "FAILED"

    assert (
        manifest["identity"]["checks"][
            "hdparm_identify_serial_matches"
        ]
        is False
    )


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

    manifest = read_manifest(output)
    identify = manifest["commands"][1]

    assert result == 1
    assert identify["timed_out"] is True
    assert identify["execution_status"] == "TIMED_OUT"
    assert identify["exit_code"] is None

    assert manifest["capture"]["status"] == "PARTIAL"
    assert manifest["collection"]["status"] == "INCOMPLETE"
    assert manifest["identity"]["status"] == "NOT_CHECKED"

    assert (
        output / "identify.stdout.bin"
    ).read_bytes() == b"Serial Number: TEST-SERIAL-0001\n"


def test_post_collection_inventory_failure_is_recorded(
    monkeypatch, tmp_path
):
    inventory_calls = []

    def fake_inventory(device, serial):
        inventory_calls.append(device)

        if len(inventory_calls) == 2:
            raise RuntimeError("simulated post-inventory failure")

        return DEVICE.copy()

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
        fake_inventory,
    )

    def fake_run_command(argv, timeout=60):
        if argv[-1] == "-V":
            return make_record(argv, stdout=b"hdparm v9.65\n")

        return make_record(
            argv,
            stdout=b"Serial Number: TEST-SERIAL-0001\n",
        )

    monkeypatch.setattr(collector, "run_command", fake_run_command)

    output = tmp_path / "hdparm-post-inventory-failure"

    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    manifest = read_manifest(output)

    assert result == 1
    assert manifest["collection"]["status"] == "INCOMPLETE"
    assert manifest["capture"]["status"] == "COMPLETE"
    assert manifest["identity"]["status"] == "FAILED"
    assert manifest["target"]["observations"]["after"] is None

    assert (
        manifest["identity"]["checks"][
            "post_collection_inventory_error"
        ]
        == "simulated post-inventory failure"
    )


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

    manifest = read_manifest(output)

    assert result == 1
    assert manifest["collection"]["status"] == "INCOMPLETE"
    assert manifest["capture"]["status"] == "INCOMPLETE"
    assert manifest["identity"]["status"] == "NOT_CHECKED"
    assert manifest["collection"]["error"]["type"] == "OSError"
    assert manifest["safety"]["destructive_commands_executed"] is False


def test_identity_verified_when_unrelated_version_command_times_out(
    monkeypatch, tmp_path
):
    def fake_run_command(argv, timeout=60):
        if argv[-1] == "-V":
            return make_record(
                argv,
                stdout=b"Partial version output",
                exit_code=None,
                timed_out=True,
            )

        return make_record(
            argv,
            stdout=b"Serial Number: TEST-SERIAL-0001\n",
        )

    setup_collector(monkeypatch, fake_run_command)

    output = tmp_path / "hdparm-version-timeout"
    result = collector.collect(
        "/dev/sda",
        EXPECTED_SERIAL,
        output,
    )

    manifest = read_manifest(output)

    assert result == 1
    assert manifest["collection"]["status"] == "INCOMPLETE"
    assert manifest["capture"]["status"] == "PARTIAL"
    assert manifest["identity"]["status"] == "VERIFIED"
