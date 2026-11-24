#!/usr/bin/env python3
"""Read-only hdparm evidence collector for OSE Evidence Schema 2.0."""

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



def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def extract_ata_serial(output):
    """Extract the ATA serial number from hdparm IDENTIFY output."""
    text = output.decode("utf-8", errors="replace")
    match = re.search(
        r"(?mi)^\s*Serial Number:\s*([^\s\uFFFD]+)",
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
    """Execute a read-only command and preserve its raw output."""
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
        "extensions": {
            "exit_code_zero": (
                exit_code == 0 and not timed_out
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
        "collector": "OSE hdparm read-only collector",
        "adapter": "hdparm",
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
            "hdparm": {
                "executable": executable,
                "exit_code_semantics": (
                    "hdparm command exit codes are interpreted as "
                    "command outcomes. A nonzero exit code indicates "
                    "command failure but does not by itself mean "
                    "that captured stdout/stderr evidence is incomplete."
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


def collect(device, expected_serial, output_path):
    output_dir = Path(output_path)

    if output_dir.is_symlink():
        raise RuntimeError(
            "Output path must not be a symbolic link"
        )

    if output_dir.exists():
        raise RuntimeError(
            "Output directory already exists; choose a new path"
        )

    if not expected_serial or not expected_serial.strip():
        raise ValueError("An expected device serial is required")

    executable = shutil.which("hdparm")
    sudo = shutil.which("sudo")

    if not executable:
        raise RuntimeError("hdparm was not found in PATH")

    if not sudo:
        raise RuntimeError("sudo was not found in PATH")

    device_before = get_device_inventory(device, expected_serial)
    validate_device(device_before, expected_serial)

    output_dir.mkdir(parents=True, exist_ok=False)

    collection_id = str(uuid.uuid4())
    started_utc = utc_now()

    command_definitions = (
        ("version", [executable, "-V"]),
        (
            "identify",
            [sudo, "-n", executable, "-I", device],
        ),
    )

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
            command = build_command_record(name, record, [])
            commands.append(command)

            command_artifacts = save_command_output(
                output_dir,
                name,
                record,
            )
            command["artifact_ids"] = [
                artifact["artifact_id"]
                for artifact in command_artifacts
            ]
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
            validate_device(device_after, expected_serial)
        except Exception as exc:
            post_check_error = str(exc)

    identity_checks = {}
    identity_status = "NOT_CHECKED"

    identify_completed = any(
        command["name"] == "identify"
        and command["execution_status"] == "COMPLETED"
        for command in commands
    )

    if collection_error is None and identify_completed:
        reported_serial = extract_ata_serial(
            raw_outputs.get("identify", b"")
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
            "hdparm_identify_serial": reported_serial,
            "hdparm_identify_serial_matches": (
                reported_serial == expected_serial
            ),
        }

        if post_check_error is not None:
            identity_status = "FAILED"
        else:
            identity_status = (
                "VERIFIED"
                if all([
                    identity_checks["linux_serial_before_matches"],
                    identity_checks["linux_serial_after_matches"],
                    identity_checks[
                        "linux_usb_transport_after_matches"
                    ],
                    identity_checks[
                        "hdparm_identify_serial_matches"
                    ],
                ])
                else "FAILED"
            )

    all_commands_present = (
        len(commands) == len(command_definitions)
    )

    all_commands_completed = (
        all_commands_present
        and all(
            command["execution_status"] == "COMPLETED"
            for command in commands
        )
    )

    if (
        all_commands_completed
        and len(artifacts) == len(command_definitions) * 2
    ):
        capture_status = "COMPLETE"
    elif artifacts:
        capture_status = "PARTIAL"
    else:
        capture_status = "INCOMPLETE"

    collection_complete = (
        collection_error is None
        and all_commands_completed
        and post_check_error is None
    )

    collection_status = (
        "COMPLETE" if collection_complete else "INCOMPLETE"
    )

    finished_utc = utc_now()

    evidence = build_manifest(
        collection_id=collection_id,
        started_utc=started_utc,
        finished_utc=finished_utc,
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
    print("No erase, security, or write commands were executed.")

    commands_successful = (
        all_commands_completed
        and all(
            command["exit_code"] == 0
            for command in commands
        )
    )

    return (
        0
        if (
            collection_complete
            and capture_status == "COMPLETE"
            and identity_status == "VERIFIED"
            and commands_successful
        )
        else 1
    )


def main():
    parser = argparse.ArgumentParser(
        description="OSE read-only hdparm evidence collector"
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
