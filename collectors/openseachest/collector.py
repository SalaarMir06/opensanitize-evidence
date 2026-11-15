
#!/usr/bin/env python3
"""Read-only openSeaChest evidence collector for OSE."""

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


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def run_command(argv, timeout=60):
    """Run a command and retain its stdout/stderr as raw bytes."""
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


def get_device_inventory(device):
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

    if not target or target.get("type") != "disk":
        raise RuntimeError("Selected path is not a detected whole disk")

    return target


def validate_device(target, expected_serial):
    if (target.get("serial") or "").strip() != expected_serial:
        raise RuntimeError("Linux device serial does not match expected serial")

    if target.get("tran") != "usb":
        raise RuntimeError("Selected device is not reported as USB-connected")


def save_command_output(output_dir, name, record):
    stdout_name = f"{name}.stdout.bin"
    stderr_name = f"{name}.stderr.bin"

    stdout_path = output_dir / stdout_name
    stderr_path = output_dir / stderr_name

    stdout_path.write_bytes(record["stdout"])
    stderr_path.write_bytes(record["stderr"])

    return {
        "started_utc": record["started_utc"],
        "finished_utc": record["finished_utc"],
        "duration_seconds": record["duration_seconds"],
        "argv": record["argv"],
        "exit_code": record["exit_code"],
        "timed_out": record["timed_out"],
        "stdout_file": stdout_name,
        "stdout_size_bytes": len(record["stdout"]),
        "stdout_sha256": sha256_bytes(record["stdout"]),
        "stderr_file": stderr_name,
        "stderr_size_bytes": len(record["stderr"]),
        "stderr_sha256": sha256_bytes(record["stderr"]),
        "successful": (
            record["exit_code"] == 0 and not record["timed_out"]
        ),
    }


def extract_ata_serial(sat_output):
    text = sat_output.decode("utf-8", errors="replace")

    if "ATA Reported Information:" not in text:
        return None

    ata_section = text.split("ATA Reported Information:", 1)[1]
    match = re.search(
        r"(?m)^\s*Serial Number:\s*(\S+)\s*$",
        ata_section,
    )

    return match.group(1) if match else None


def collect(device, expected_serial, output_path):
    output_dir = Path(output_path)

    # Never overwrite or reuse an existing evidence directory.
    if output_dir.is_symlink():
        raise RuntimeError("Output path must not be a symbolic link")

    if output_dir.exists():
        raise RuntimeError("Output directory already exists; choose a new path")

    executable = shutil.which("openSeaChest_Info")
    sudo = shutil.which("sudo")

    if not executable:
        raise RuntimeError("openSeaChest_Info was not found in PATH")

    if not sudo:
        raise RuntimeError("sudo was not found in PATH")

    device_before = get_device_inventory(device)
    validate_device(device_before, expected_serial)

    output_dir.mkdir(parents=True, exist_ok=False)

    commands = {
        "version": [executable, "--version"],
        "usb_scan": [
            sudo, "-n", executable, "--scan", "-F", "usb"
        ],
        "device_info": [
            sudo, "-n", executable, "-d", device, "-i"
        ],
        "sat_info": [
            sudo, "-n", executable, "-d", device, "--SATInfo"
        ],
    }

    records = {}
    sat_output = b""
    scan_output = b""

    try:
        for name, argv in commands.items():
            print(f"Collecting: {name}")
            raw_record = run_command(argv)
            records[name] = save_command_output(
                output_dir, name, raw_record
            )

            # Retain raw SAT output temporarily for ATA serial validation.
            if name == "sat_info":
                sat_output = raw_record["stdout"]

            if name == "usb_scan":
                scan_output = raw_record["stdout"]

    except Exception as exc:
        incomplete_evidence = {
            "schema_version": "1.2",
            "collector": "OSE openSeaChest read-only collector",
            "collection_started_utc": (
                next(iter(records.values()))["started_utc"]
                if records else utc_now()
            ),
            "collection_finished_utc": utc_now(),
            "device_before": device_before,
            "device_after": None,
            "expected_serial": expected_serial,
            "openSeaChest_executable": executable,
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
                json.dumps(
                    incomplete_evidence,
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )
        except OSError as write_error:
            print(
                f"Could not write incomplete collection manifest: "
                f"{write_error}",
                file=sys.stderr,
            )

        print(
            f"Collection incomplete: {exc}",
            file=sys.stderr,
        )
        return 1


    device_after = None
    post_check_error = None

    try:
        device_after = get_device_inventory(device)
        validate_device(device_after, expected_serial)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        post_check_error = str(exc)

    ata_serial = extract_ata_serial(sat_output)
    scan_text = scan_output.decode("utf-8", errors="replace")

    identity_checks = {
        "linux_serial_before_matches": True,
        "linux_serial_after_matches": device_after is not None
        and (device_after.get("serial") or "").strip() == expected_serial,
        "usb_scan_contains_expected_serial": expected_serial in scan_text,
        "ata_reported_serial": ata_serial,
        "ata_serial_matches": ata_serial == expected_serial,
        "post_collection_inventory_error": post_check_error,
    }

    commands_successful = all(
        item["successful"] for item in records.values()
    )

    identity_successful = (
        identity_checks["linux_serial_after_matches"]
        and identity_checks["usb_scan_contains_expected_serial"]
        and identity_checks["ata_serial_matches"]
        and post_check_error is None
    )

    evidence = {
        "schema_version": "1.1",
        "collector": "OSE openSeaChest read-only collector",
        "collection_started_utc": records["version"]["started_utc"],
        "collection_finished_utc": utc_now(),
        "device_before": device_before,
        "device_after": device_after,
        "expected_serial": expected_serial,
        "openSeaChest_executable": executable,
        "commands": records,
        "identity_checks": identity_checks,
        "collection_status": (
            "SUCCESS" if commands_successful and identity_successful
            else "FAILED"
        ),
        "safety": {
            "read_only_collection": True,
            "destructive_commands_executed": False,
        },
    }

    (output_dir / "collection.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"\nCollection saved to: {output_dir}")
    print(f"Collection status: {evidence['collection_status']}")
    print(f"ATA-reported serial: {ata_serial}")
    print("No erase or sanitize commands were executed.")

    return 0 if evidence["collection_status"] == "SUCCESS" else 1


def main():
    parser = argparse.ArgumentParser(
        description="OSE read-only openSeaChest evidence collector"
    )
    parser.add_argument("--device", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        return collect(args.device, args.serial, args.output)
    except (
        OSError, ValueError, RuntimeError, subprocess.SubprocessError
    ) as exc:
        print(f"Collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
