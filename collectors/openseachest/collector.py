#!/usr/bin/env python3
"""Read-only openSeaChest evidence collector for OSE Schema 2.0."""

import argparse
import hashlib
import json
import os
import stat
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ose.evidence_schema import validate_manifest


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def run_command(argv, timeout=60):
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
            "argv": list(argv),
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
            "argv": list(argv),
            "exit_code": None,
            "stdout": exc.stdout or b"",
            "stderr": exc.stderr or b"",
            "timed_out": True,
        }


def get_device_inventory(device):
    result = subprocess.run(
        [
            "lsblk",
            "-J",
            "-b",
            "-o",
            "PATH,TYPE,SIZE,MODEL,SERIAL,TRAN",
            device,
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    data = json.loads(result.stdout)

    def find_device(devices):
        for item in devices:
            if item.get("path") == device:
                return item

            found = find_device(item.get("children", []))
            if found:
                return found

        return None

    inventory = find_device(data.get("blockdevices", []))

    if inventory is None:
        raise RuntimeError(
            f"Device not found in lsblk inventory: {device}"
        )

    if inventory.get("type") != "disk":
        raise RuntimeError(
            f"Target is not a whole disk: {device}"
        )

    return inventory


def validate_device(target, expected_serial):
    actual_serial = (target.get("serial") or "").strip()

    if actual_serial != expected_serial:
        raise RuntimeError(
            "Device serial mismatch: "
            f"expected {expected_serial!r}, got {actual_serial!r}"
        )

    if (target.get("tran") or "").lower() != "usb":
        raise RuntimeError(
            "Target device is not connected through USB"
        )


def save_command_output(output_dir, name, record):
    """Save raw command streams and return Schema 2.0 artifacts."""

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


def extract_ata_serial(sat_output):
    text = sat_output.decode("utf-8", errors="replace")

    match = re.search(
        r"ATA Reported Information:(.*)",
        text,
        re.DOTALL,
    )

    if not match:
        return None

    serial_match = re.search(
        r"Serial Number:\s*(\S+)",
        match.group(1),
    )

    return serial_match.group(1) if serial_match else None


def build_command_record(name, record, artifacts):
    timed_out = record["timed_out"]

    return {
        "command_id": f"cmd-{name}",
        "name": name,
        "argv": record["argv"],
        "started_utc": record["started_utc"],
        "finished_utc": record["finished_utc"],
        "duration_seconds": record["duration_seconds"],
        "exit_code": record["exit_code"],
        "timed_out": timed_out,
        "execution_status": (
            "TIMED_OUT" if timed_out else "COMPLETED"
        ),
        "artifact_ids": [
            artifact["artifact_id"] for artifact in artifacts
        ],
        "extensions": {
            "exit_code_zero": (
                record["exit_code"] == 0 and not timed_out
            ),
        },
    }


def build_manifest(
    collection_id,
    started_utc,
    finished_utc,
    expected_serial,
    executable,
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
        "collector": "OSE openSeaChest read-only collector",
        "adapter": "openSeaChest",
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
            "openseachest": {
                "executable": executable,
            },
        },
    }


def validate_output_artifacts(output_dir, artifacts):
    """Verify declared artifacts and reject unsafe output directory contents."""

    output_dir = Path(output_dir)

    if output_dir.is_symlink() or not output_dir.is_dir():
        raise ValueError("Collection output is not a regular directory")

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
            or any(
                ord(char) < 32 or ord(char) == 127
                for char in relative_path
            )
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
        unexpected = sorted(actual_directories - expected_directories)

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


def collect(device, expected_serial, output_path):
    output_dir = Path(output_path)

    if output_dir.is_symlink():
        raise RuntimeError(
            "Output directory must not be a symlink"
        )

    if output_dir.exists():
        raise RuntimeError(
            f"Output directory already exists: {output_dir}"
        )

    executable = shutil.which("openSeaChest_Info")
    sudo = shutil.which("sudo")

    if not executable:
        raise RuntimeError("openSeaChest_Info not found")

    if not sudo:
        raise RuntimeError("sudo not found")

    device_before = get_device_inventory(device)
    validate_device(device_before, expected_serial)

    output_dir.mkdir(parents=True, exist_ok=False)

    collection_id = str(uuid.uuid4())
    started_utc = utc_now()

    command_definitions = [
        (
            "version",
            [executable, "--version"],
        ),
        (
            "usb_scan",
            [sudo, "-n", executable, "--scan", "-F", "usb"],
        ),
        (
            "device_info",
            [sudo, "-n", executable, "-d", device, "-i"],
        ),
        (
            "sat_info",
            [sudo, "-n", executable, "-d", device, "--SATInfo"],
        ),
    ]

    commands = []
    artifacts = []
    sat_output = b""
    scan_output = b""
    collection_error = None
    post_check_error = None
    device_after = None

    try:
        for name, argv in command_definitions:
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

            if name == "sat_info":
                sat_output = record["stdout"]

            elif name == "usb_scan":
                scan_output = record["stdout"]

    except Exception as exc:
        collection_error = {
            "type": type(exc).__name__,
            "message": str(exc),
        }

    if collection_error is None:
        try:
            device_after = get_device_inventory(device)

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
        ata_serial = extract_ata_serial(sat_output)
        scan_text = scan_output.decode(
            "utf-8",
            errors="replace",
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
            "usb_scan_contains_expected_serial": (
                expected_serial in scan_text
            ),
            "ata_reported_serial": ata_serial,
            "ata_serial_matches": (
                ata_serial == expected_serial
            ),
        }

        identity_successful = (
            identity_checks["linux_serial_before_matches"]
            and identity_checks["linux_serial_after_matches"]
            and identity_checks[
                "linux_usb_transport_after_matches"
            ]
            and identity_checks[
                "usb_scan_contains_expected_serial"
            ]
            and identity_checks["ata_serial_matches"]
            and post_check_error is None
        )

        identity_status = (
            "VERIFIED" if identity_successful else "FAILED"
        )

    all_commands_completed = (
        len(commands) == len(command_definitions)
        and all(
            command["execution_status"] == "COMPLETED"
            for command in commands
        )
    )

    capture_complete = (
        all_commands_completed
        and len(artifacts) == len(command_definitions) * 2
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
        and all_commands_completed
    )

    commands_successful = all(
        command["exit_code"] == 0
        and not command["timed_out"]
        for command in commands
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
    print("No erase or sanitize commands were executed.")

    return (
        0
        if collection_complete
        and capture_complete
        and identity_status == "VERIFIED"
        and commands_successful
        else 1
    )


def main():
    parser = argparse.ArgumentParser(
        description="OSE read-only openSeaChest evidence collector"
    )
    parser.add_argument("--device", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        return collect(
            args.device,
            args.serial,
            args.output,
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
