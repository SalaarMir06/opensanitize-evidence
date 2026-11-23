#!/usr/bin/env python3
"""Read-only smartctl evidence collector for OSE Schema 2.0."""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ose.evidence_schema import validate_manifest


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

COMMAND_DEFINITIONS = (
    ("version", "version"),
    ("scan", "scan"),
    ("device_info", "device_info"),
    ("device_full", "device_full"),
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def decode_exit_status(exit_code):
    """Decode smartctl's eight-bit ATA exit-status bitmask."""
    if (
        isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not 0 <= exit_code <= 255
    ):
        raise ValueError(
            "smartctl exit code must be an integer from 0 to 255"
        )

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
        raise RuntimeError(
            "Linux device serial does not match expected serial"
        )

    if (target.get("tran") or "").lower() != "usb":
        raise RuntimeError(
            "Selected device is not reported as USB-connected"
        )


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

    def find_device(items):
        for item in items:
            if item.get("path") == device:
                return item

            found = find_device(item.get("children") or [])
            if found is not None:
                return found

        return None

    target = find_device(inventory.get("blockdevices", []))

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
            "duration_seconds": round(
                time.monotonic() - start_time, 3
            ),
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
            "duration_seconds": round(
                time.monotonic() - start_time, 3
            ),
            "argv": argv,
            "exit_code": None,
            "stdout": exc.stdout or b"",
            "stderr": exc.stderr or b"",
            "timed_out": True,
        }


def save_command_output(output_dir, name, record):
    """Save raw stdout/stderr and return Schema 2.0 artifacts."""
    streams = (
        ("stdout", record["stdout"]),
        ("stderr", record["stderr"]),
    )

    artifacts = []
    created_paths = []

    try:
        for role, data in streams:
            artifact_id = f"{name}-{role}"
            filename = f"{name}.{role}.bin"
            artifact_path = output_dir / filename

            created_paths.append(artifact_path)
            artifact_path.write_bytes(data)

            artifacts.append({
                "artifact_id": artifact_id,
                "role": role,
                "path": filename,
                "media_type": "application/octet-stream",
                "size_bytes": len(data),
                "hash": {
                    "algorithm": "sha256",
                    "value": sha256_bytes(data),
                },
            })

    except Exception:
        for artifact_path in created_paths:
            try:
                artifact_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    return artifacts


def build_command_record(name, record, artifacts):
    timed_out = record["timed_out"]
    exit_code = record["exit_code"]

    extensions = {
        "exit_code_zero": (
            exit_code == 0 and not timed_out
        ),
        "smartctl_status": (
            decode_exit_status(exit_code)
            if isinstance(exit_code, int)
            and not isinstance(exit_code, bool)
            and 0 <= exit_code <= 255
            else None
        ),
    }

    return {
        "command_id": f"cmd-{name}",
        "name": name,
        "argv": record["argv"],
        "started_utc": record["started_utc"],
        "finished_utc": record["finished_utc"],
        "duration_seconds": record["duration_seconds"],
        "exit_code": exit_code,
        "timed_out": timed_out,
        "execution_status": (
            "TIMED_OUT" if timed_out else "COMPLETED"
        ),
        "artifact_ids": [
            artifact["artifact_id"] for artifact in artifacts
        ],
        "extensions": extensions,
    }


def build_manifest(
    collection_id,
    started_utc,
    finished_utc,
    expected_serial,
    executable,
    device_type,
    device_before,
    device_after,
    commands,
    artifacts,
    identity_checks,
    collection_status,
    capture_status,
    identity_status,
    collection_error=None,
    post_check_error=None,
):
    collection = {
        "collection_id": collection_id,
        "collector": "OSE smartctl read-only collector",
        "adapter": "smartctl",
        "started_utc": started_utc,
        "finished_utc": finished_utc,
        "status": collection_status,
    }

    if collection_error is not None:
        collection["error"] = collection_error

    checks = dict(identity_checks)

    if post_check_error is not None:
        checks["post_collection_inventory_error"] = (
            post_check_error
        )

    return {
        "schema_version": "2.0",
        "collection": collection,
        "target": {
            "expected_identity": {
                "serial": expected_serial,
            },
            "observations": {
                "before": device_before,
                "after": device_after,
            },
        },
        "identity": {
            "status": identity_status,
            "checks": checks,
        },
        "commands": commands,
        "artifacts": artifacts,
        "capture": {
            "status": capture_status,
        },
        "assessment": {
            "status": "NOT_ASSESSED",
        },
        "safety": {
            "read_only_collection": True,
            "destructive_commands_executed": False,
        },
        "extensions": {
            "smartctl": {
                "executable": executable,
                "device_type": device_type,
                "exit_status_semantics": (
                    "smartctl exit codes are bitmasks. A nonzero "
                    "exit code does not by itself mean evidence "
                    "capture failed."
                ),
                "diagnostic_assessment": "NOT_ASSESSED",
            },
        },
    }


def validate_output_artifacts(output_dir, artifacts):
    """Verify declared artifacts and reject unsafe output contents."""
    output_dir = Path(output_dir)

    if output_dir.is_symlink() or not output_dir.is_dir():
        raise ValueError(
            "Collection output is not a regular directory"
        )

    root = output_dir.resolve(strict=True)
    expected_paths = {}

    for artifact in artifacts:
        relative_path = artifact["path"]

        if (
            not isinstance(relative_path, str)
            or not relative_path
            or relative_path.startswith("/")
            or "\\" in relative_path
            or any(
                part in {"", ".", ".."}
                for part in relative_path.split("/")
            )
            or any(ord(char) < 32 or ord(char) == 127
                   for char in relative_path)
            or re.match(r"^[A-Za-z]:", relative_path)
        ):
            raise ValueError(
                f"Unsafe artifact path: {relative_path!r}"
            )

        if relative_path in expected_paths:
            raise ValueError(
                f"Duplicate artifact path: {relative_path}"
            )

        expected_paths[relative_path] = artifact
        artifact_path = output_dir

        for part in relative_path.split("/"):
            artifact_path = artifact_path / part

            if artifact_path.is_symlink():
                raise ValueError(
                    f"Symlink found in artifact path: {relative_path}"
                )

        try:
            file_stat = artifact_path.lstat()
        except OSError as exc:
            raise ValueError(
                f"Cannot access artifact {relative_path}: {exc}"
            ) from exc

        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(
                f"Artifact is not a regular file: {relative_path}"
            )

        resolved = artifact_path.resolve(strict=True)

        if not resolved.is_relative_to(root):
            raise ValueError(
                f"Artifact escapes collection directory: {relative_path}"
            )

        data = artifact_path.read_bytes()

        if len(data) != artifact["size_bytes"]:
            raise ValueError(
                f"Artifact size mismatch: {relative_path}"
            )

        if sha256_bytes(data) != artifact["hash"]["value"]:
            raise ValueError(
                f"Artifact SHA-256 mismatch: {relative_path}"
            )

    actual_paths = set()
    actual_directories = set()

    def raise_walk_error(error):
        raise error

    for current, directories, filenames in os.walk(
        output_dir,
        topdown=True,
        followlinks=False,
        onerror=raise_walk_error,
    ):
        current_path = Path(current)

        for directory in directories:
            directory_path = current_path / directory

            if directory_path.is_symlink():
                raise ValueError(
                    f"Symlink directory found: {directory_path}"
                )

            actual_directories.add(
                directory_path.relative_to(output_dir).as_posix()
            )

        for filename in filenames:
            file_path = current_path / filename
            file_stat = file_path.lstat()

            if not stat.S_ISREG(file_stat.st_mode):
                raise ValueError(
                    f"Non-regular output file found: {file_path}"
                )

            actual_paths.add(
                file_path.relative_to(output_dir).as_posix()
            )

    expected_set = set(expected_paths)

    if actual_paths != expected_set:
        missing = sorted(expected_set - actual_paths)
        unexpected = sorted(actual_paths - expected_set)

        raise ValueError(
            "Collection output does not match declared artifacts. "
            f"Missing: {missing}; unexpected: {unexpected}"
        )

    expected_directories = set()

    for relative_path in expected_set:
        parts = relative_path.split("/")
        for index in range(1, len(parts)):
            expected_directories.add("/".join(parts[:index]))

    if actual_directories != expected_directories:
        unexpected = sorted(
            actual_directories - expected_directories
        )
        raise ValueError(
            "Collection output contains unlisted directories: "
            f"{unexpected}"
        )


def write_manifest(output_dir, evidence):
    errors = validate_manifest(evidence)

    if errors:
        raise ValueError(
            "Generated evidence manifest failed Schema 2.0 "
            "validation:\n" + "\n".join(errors)
        )

    validate_output_artifacts(
        output_dir,
        evidence["artifacts"],
    )

    (output_dir / "collection.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def collect(device, expected_serial, output_path, device_type="sat"):
    output_dir = Path(output_path)

    if output_dir.is_symlink():
        raise RuntimeError(
            "Output directory must not be a symbolic link"
        )

    if output_dir.exists():
        raise RuntimeError(
            "Output directory already exists; choose a new path"
        )

    if device_type != "sat":
        raise ValueError(
            "Only the explicitly supported device type 'sat' is allowed"
        )

    executable = shutil.which("smartctl")
    sudo = shutil.which("sudo")

    if not executable:
        raise RuntimeError("smartctl was not found in PATH")

    if not sudo:
        raise RuntimeError("sudo was not found in PATH")

    device_before = get_device_inventory(device, expected_serial)

    output_dir.mkdir(parents=True, exist_ok=False)

    collection_id = str(uuid.uuid4())
    started_utc = utc_now()

    command_definitions = [
        ("version", [executable, "--version"]),
        ("scan", [sudo, "-n", executable, "--scan-open"]),
        (
            "device_info",
            [sudo, "-n", executable, "-i", "-d", device_type, device],
        ),
        (
            "device_full",
            [sudo, "-n", executable, "-x", "-d", device_type, device],
        ),
    ]

    commands = []
    artifacts = []
    raw_outputs = {}
    collection_error = None
    post_check_error = None
    device_after = None

    try:
        for name, argv in command_definitions:
            print(f"Collecting: {name}")

            record = run_command(argv)
            command_artifacts = save_command_output(
                output_dir,
                name,
                record,
            )

            command = build_command_record(
                name,
                record,
                command_artifacts,
            )

            commands.append(command)
            artifacts.extend(command_artifacts)
            raw_outputs[name] = record["stdout"]

    except Exception as exc:
        collection_error = {
            "type": type(exc).__name__,
            "message": str(exc),
        }

    if collection_error is None:
        try:
            device_after = get_device_inventory(
                device,
                expected_serial,
            )
        except (
            OSError,
            ValueError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as exc:
            post_check_error = str(exc)

    identity_checks = {}
    identity_status = "NOT_CHECKED"

    if collection_error is None:
        info_serial = extract_ata_serial(
            raw_outputs.get("device_info", b"")
        )
        full_serial = extract_ata_serial(
            raw_outputs.get("device_full", b"")
        )

        identity_checks = {
            "linux_serial_before_matches": (
                (device_before.get("serial") or "").strip()
                == expected_serial
            ),
            "linux_serial_after_matches": (
                device_after is not None
                and (
                    device_after.get("serial") or ""
                ).strip() == expected_serial
            ),
            "linux_usb_transport_after_matches": (
                device_after is not None
                and (
                    device_after.get("tran") or ""
                ).lower() == "usb"
            ),
            "smartctl_info_serial": info_serial,
            "smartctl_info_serial_matches": (
                info_serial == expected_serial
            ),
            "smartctl_full_report_serial": full_serial,
            "smartctl_full_report_serial_matches": (
                full_serial == expected_serial
            ),
        }

        identity_successful = all([
            identity_checks["linux_serial_before_matches"],
            identity_checks["linux_serial_after_matches"],
            identity_checks["linux_usb_transport_after_matches"],
            identity_checks["smartctl_info_serial_matches"],
            identity_checks["smartctl_full_report_serial_matches"],
            post_check_error is None,
        ])

        identity_status = (
            "VERIFIED" if identity_successful else "FAILED"
        )

    capture_complete = (
        len(commands) == len(command_definitions)
        and len(artifacts) == len(command_definitions) * 2
        and all(
            command["execution_status"] == "COMPLETED"
            for command in commands
        )
    )

    if capture_complete:
        capture_status = "COMPLETE"
    elif artifacts:
        capture_status = "PARTIAL"
    else:
        capture_status = "INCOMPLETE"

    collection_complete = (
        collection_error is None
        and post_check_error is None
        and len(commands) == len(command_definitions)
        and all(
            command["execution_status"] == "COMPLETED"
            for command in commands
        )
    )

    collection_status = (
        "COMPLETE" if collection_complete else "INCOMPLETE"
    )

    evidence = build_manifest(
        collection_id=collection_id,
        started_utc=started_utc,
        finished_utc=utc_now(),
        expected_serial=expected_serial,
        executable=executable,
        device_type=device_type,
        device_before=device_before,
        device_after=device_after,
        commands=commands,
        artifacts=artifacts,
        identity_checks=identity_checks,
        collection_status=collection_status,
        capture_status=capture_status,
        identity_status=identity_status,
        collection_error=collection_error,
        post_check_error=post_check_error,
    )

    write_manifest(output_dir, evidence)

    print(f"\nCollection saved to: {output_dir}")
    print(f"Collection status: {collection_status}")
    print(f"Capture status: {capture_status}")
    print(f"Identity status: {identity_status}")
    print("Assessment status: NOT_ASSESSED")
    print("No self-tests, erase, or sanitize commands were executed.")

    # Nonzero smartctl exit statuses are diagnostic evidence, not
    # automatic capture failures. Preserve their meaning in extensions.
    return (
        0
        if collection_complete
        and capture_complete
        and identity_status == "VERIFIED"
        else 1
    )


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
        OSError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"Collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
