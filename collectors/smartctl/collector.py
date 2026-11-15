#!/usr/bin/env python3
"""Read-only smartctl evidence collector for OSE."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


EXIT_STATUS_BITS = {
    0: "command_line_parse_error",
    1: "device_open_or_identify_error",
    2: "smart_command_or_checksum_error",
    3: "disk_failing",
    4: "prefail_attribute_threshold_now",
    5: "attribute_threshold_failed_in_past",
    6: "error_log_records",
    7: "selftest_log_records",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def decode_exit_status(exit_code):
    """Decode the smartctl eight-bit ATA exit-status bitmask."""
    if not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        raise ValueError("smartctl exit code must be an integer from 0 to 255")

    flags = [
        name
        for bit, name in EXIT_STATUS_BITS.items()
        if exit_code & (1 << bit)
    ]

    return {
        "raw_exit_code": exit_code,
        "flags": flags,
        "disk_failing": bool(exit_code & 8),
    }


def extract_ata_serial(output):
    """Extract the serial number from smartctl text output."""
    text = output.decode("utf-8", errors="replace")
    match = re.search(
        r"(?mi)^\s*Serial Number:\s*(\S+)\s*$",
        text,
    )
    return match.group(1) if match else None


def validate_device(target, expected_serial):
    if target.get("type") != "disk":
        raise RuntimeError("Selected path is not a whole disk")

    if (target.get("serial") or "").strip() != expected_serial:
        raise RuntimeError("Linux device serial does not match expected serial")

    if target.get("tran") != "usb":
        raise RuntimeError("Selected device is not reported as USB-connected")


def get_device_inventory(device, expected_serial):
    result = subprocess.run(
        [
            "lsblk", "-J", "-b",
            "-o", "PATH,TYPE,SIZE,MODEL,SERIAL,TRAN",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    inventory = json.loads(result.stdout)
    target = next(
        (
            item for item in inventory.get("blockdevices", [])
            if item.get("path") == device
        ),
        None,
    )

    if target is None:
        raise RuntimeError("Selected device was not found by lsblk")

    validate_device(target, expected_serial)
    return target


def run_command(argv, timeout=60):
    """Execute a command and preserve its raw output."""
    started = utc_now()
    start_time = time.monotonic()

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

        return {
            "started_utc": started,
            "finished_utc": utc_now(),
            "duration_seconds": round(time.monotonic() - start_time, 3),
            "argv": argv,
            "exit_code": result.returncode,
            "stdout": result.stdout or b"",
            "stderr": result.stderr or b"",
            "timed_out": False,
        }

    except subprocess.TimeoutExpired as exc:
        return {
            "started_utc": started,
            "finished_utc": utc_now(),
            "duration_seconds": round(time.monotonic() - start_time, 3),
            "argv": argv,
            "exit_code": None,
            "stdout": exc.stdout or b"",
            "stderr": exc.stderr or b"",
            "timed_out": True,
        }


def save_command_output(output_dir, name, record):
    stdout_name = f"{name}.stdout.bin"
    stderr_name = f"{name}.stderr.bin"

    stdout = record["stdout"]
    stderr = record["stderr"]

    (output_dir / stdout_name).write_bytes(stdout)
    (output_dir / stderr_name).write_bytes(stderr)

    exit_code = record["exit_code"]
    capture_complete = (
        not record["timed_out"] and exit_code is not None
    )

    metadata = {
        "started_utc": record["started_utc"],
        "finished_utc": record["finished_utc"],
        "duration_seconds": record["duration_seconds"],
        "argv": record["argv"],
        "exit_code": exit_code,
        "timed_out": record["timed_out"],
        "stdout_file": stdout_name,
        "stdout_size_bytes": len(stdout),
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_file": stderr_name,
        "stderr_size_bytes": len(stderr),
        "stderr_sha256": sha256_bytes(stderr),
        "capture_complete": capture_complete,
        "exit_code_zero": exit_code == 0 and not record["timed_out"],
    }

    if isinstance(exit_code, int) and 0 <= exit_code <= 255:
        metadata["smartctl_status"] = decode_exit_status(exit_code)
    else:
        metadata["smartctl_status"] = None

    return metadata


def collect(device, expected_serial, output_path, device_type="sat"):
    output_dir = Path(output_path)

    if output_dir.is_symlink():
        raise RuntimeError("Output path must not be a symbolic link")

    if output_dir.exists():
        raise RuntimeError("Output directory already exists; choose a new path")

    if device_type != "sat":
        raise ValueError("Only the explicitly supported device type 'sat' is allowed")

    executable = shutil.which("smartctl")
    sudo = shutil.which("sudo")

    if not executable:
        raise RuntimeError("smartctl was not found in PATH")

    if not sudo:
        raise RuntimeError("sudo was not found in PATH")

    device_before = get_device_inventory(device, expected_serial)
    validate_device(device_before, expected_serial)

    output_dir.mkdir(parents=True, exist_ok=False)

    commands = {
        "version": [executable, "--version"],
        "scan": [sudo, "-n", executable, "--scan-open"],
        "device_info": [
            sudo, "-n", executable, "-i", "-d", device_type, device
        ],
        "device_full": [
            sudo, "-n", executable, "-x", "-d", device_type, device
        ],
    }

    records = {}
    raw_outputs = {}

    try:
        for name, argv in commands.items():
            print(f"Collecting: {name}")
            raw = run_command(argv)
            raw_outputs[name] = raw["stdout"]
            records[name] = save_command_output(output_dir, name, raw)

    except Exception as exc:
        incomplete = {
            "schema_version": "1.0",
            "collector": "OSE smartctl read-only collector",
            "collection_started_utc": (
                next(iter(records.values()))["started_utc"]
                if records else utc_now()
            ),
            "collection_finished_utc": utc_now(),
            "device_before": device_before,
            "device_after": None,
            "expected_serial": expected_serial,
            "device_type": device_type,
            "smartctl_executable": executable,
            "commands": records,
            "collection_status": "INCOMPLETE",
            "collection_error": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
            "safety": {
                "read_only_collection": True,
                "destructive_commands_executed": False,
            },
        }

        try:
            (output_dir / "collection.json").write_text(
                json.dumps(incomplete, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError as write_error:
            print(f"Could not write incomplete manifest: {write_error}",
                  file=sys.stderr)

        print(f"Collection incomplete: {exc}", file=sys.stderr)
        return 1

    device_after = None
    post_check_error = None

    try:
        device_after = get_device_inventory(device, expected_serial)
        validate_device(device_after, expected_serial)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        post_check_error = str(exc)

    reported_serial = extract_ata_serial(raw_outputs.get("device_info", b""))
    full_report_serial = extract_ata_serial(raw_outputs.get("device_full", b""))

    identity_checks = {
        "linux_serial_before_matches": (
            (device_before.get("serial") or "").strip() == expected_serial
        ),
        "linux_serial_after_matches": (
            device_after is not None
            and (device_after.get("serial") or "").strip() == expected_serial
        ),
        "smartctl_info_serial": reported_serial,
        "smartctl_info_serial_matches": reported_serial == expected_serial,
        "smartctl_full_report_serial": full_report_serial,
        "smartctl_full_report_serial_matches": (
            full_report_serial == expected_serial
        ),
        "post_collection_inventory_error": post_check_error,
    }

    capture_complete = all(
        item["capture_complete"] for item in records.values()
    )

    identity_successful = all([
        identity_checks["linux_serial_before_matches"],
        identity_checks["linux_serial_after_matches"],
        identity_checks["smartctl_info_serial_matches"],
        identity_checks["smartctl_full_report_serial_matches"],
        post_check_error is None,
    ])

    evidence = {
        "schema_version": "1.0",
        "collector": "OSE smartctl read-only collector",
        "collection_started_utc": records["version"]["started_utc"],
        "collection_finished_utc": utc_now(),
        "device_before": device_before,
        "device_after": device_after,
        "expected_serial": expected_serial,
        "device_type": device_type,
        "smartctl_executable": executable,
        "commands": records,
        "identity_checks": identity_checks,
        "capture_complete": capture_complete,
        "identity_successful": identity_successful,
        "collection_status": (
            "SUCCESS" if capture_complete and identity_successful
            else "FAILED"
        ),
        "safety": {
            "read_only_collection": True,
            "destructive_commands_executed": False,
        },
        "interpretation": (
            "Collection status describes evidence capture and identity checks. "
            "It is not a sanitization verdict or a statement that the device "
            "is healthy. Review each smartctl exit-status bit and report."
        ),
    }

    (output_dir / "collection.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"\nCollection saved to: {output_dir}")
    print(f"Collection status: {evidence['collection_status']}")
    print(f"SMART-reported serial: {reported_serial}")
    print("No self-tests, erase, or sanitize commands were executed.")

    return 0 if evidence["collection_status"] == "SUCCESS" else 1


def main():
    parser = argparse.ArgumentParser(
        description="OSE read-only smartctl evidence collector"
    )
    parser.add_argument("--device", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--device-type", choices=["sat"], default="sat")
    args = parser.parse_args()

    try:
        return collect(
            args.device,
            args.serial,
            args.output,
            device_type=args.device_type,
        )
    except (
        OSError, ValueError, RuntimeError, subprocess.SubprocessError
    ) as exc:
        print(f"Collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
