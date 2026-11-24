import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

from ose.crypto import verify_signature
from ose.collection_validation import validate_collection_directory


def _read_regular_file(path: Path) -> bytes:
    """Read a regular file without following a symbolic link."""
    flags = os.O_RDONLY | os.O_NOFOLLOW
    descriptor = os.open(path, flags)

    try:
        file_stat = os.fstat(descriptor)

        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"Not a regular file: {path}")

        with os.fdopen(descriptor, "rb") as file:
            descriptor = -1
            return file.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _scan_evidence_tree(evidence_dir: Path, errors: list) -> set:
    """Find regular files and reject links or special filesystem entries."""
    actual_files = set()

    def raise_walk_error(exc):
        errors.append(f"Could not scan evidence directory: {exc}")

    for root, dirnames, filenames in os.walk(
        evidence_dir,
        topdown=True,
        followlinks=False,
        onerror=raise_walk_error,
    ):
        root_path = Path(root)
        safe_dirnames = []

        for dirname in dirnames:
            item = root_path / dirname

            try:
                item_stat = item.lstat()
            except OSError as exc:
                errors.append(f"Could not inspect evidence entry {item}: {exc}")
                continue

            if stat.S_ISLNK(item_stat.st_mode):
                errors.append(f"Symbolic link found in evidence directory: {item}")
            elif stat.S_ISDIR(item_stat.st_mode):
                safe_dirnames.append(dirname)
            else:
                errors.append(f"Non-directory entry found in evidence tree: {item}")

        dirnames[:] = safe_dirnames

        for filename in filenames:
            item = root_path / filename

            try:
                item_stat = item.lstat()
            except OSError as exc:
                errors.append(f"Could not inspect evidence entry {item}: {exc}")
                continue

            relative_name = item.relative_to(evidence_dir).as_posix()

            if stat.S_ISLNK(item_stat.st_mode):
                errors.append(f"Symbolic link found in evidence directory: {item}")
            elif stat.S_ISREG(item_stat.st_mode):
                actual_files.add(relative_name)
            else:
                errors.append(f"Non-regular file found in evidence directory: {item}")

    return actual_files


def verify_package(
    package_dir: str | Path,
    public_key_path: str | Path,
) -> dict:
    """
    Verify an evidence package's manifest signature and file integrity.

    This verifies integrity, not whether sanitization succeeded.
    """
    package_candidate = Path(package_dir).expanduser()
    public_key = Path(public_key_path)

    errors = []
    checked_files = 0

    try:
        package_stat = package_candidate.lstat()
    except OSError:
        return {
            "valid": False,
            "checked_files": 0,
            "errors": ["Package directory does not exist or cannot be inspected."],
        }

    if not stat.S_ISDIR(package_stat.st_mode):
        return {
            "valid": False,
            "checked_files": 0,
            "errors": ["Package path must be a real directory, not a symbolic link."],
        }

    package = package_candidate.resolve()
    manifest_path = package / "manifest.json"
    signature_path = package / "manifest.sig"
    evidence_dir = package / "evidence"

    try:
        public_key_stat = public_key.lstat()
    except OSError:
        return {
            "valid": False,
            "checked_files": 0,
            "errors": ["Public key file does not exist or cannot be inspected."],
        }

    if not stat.S_ISREG(public_key_stat.st_mode):
        return {
            "valid": False,
            "checked_files": 0,
            "errors": ["Public key path must be a regular file, not a symbolic link."],
        }

    try:
        public_key_bytes = _read_regular_file(public_key)
        manifest_bytes = _read_regular_file(manifest_path)
        signature_bytes = _read_regular_file(signature_path)
        signature = signature_bytes.decode("ascii").strip()

        if not verify_signature(
            manifest_bytes,
            signature,
            public_key_bytes,
        ):
            return {
                "valid": False,
                "checked_files": 0,
                "errors": ["Manifest signature is invalid."],
            }

        manifest = json.loads(manifest_bytes)

    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        return {
            "valid": False,
            "checked_files": 0,
            "errors": [f"Could not read or verify manifest: {exc}"],
        }

    if not isinstance(manifest, dict):
        return {
            "valid": False,
            "checked_files": 0,
            "errors": ["Manifest must contain a JSON object."],
        }

    if manifest.get("schema_version") != "1.0":
        errors.append("Unsupported manifest schema version.")

    if manifest.get("hash_algorithm") != "SHA-256":
        errors.append("Unsupported hash algorithm.")

    if manifest.get("signature_algorithm") != "Ed25519":
        errors.append("Unsupported signature algorithm.")

    if not isinstance(manifest.get("evidence_files"), list):
        errors.append("Manifest evidence_files must be a list.")
        entries = []
    else:
        entries = manifest["evidence_files"]

    try:
        evidence_stat = evidence_dir.lstat()
    except OSError:
        evidence_stat = None

    if evidence_stat is None or not stat.S_ISDIR(evidence_stat.st_mode):
        errors.append("Evidence directory is missing or is not a real directory.")
        actual_files = set()
    else:
        actual_files = _scan_evidence_tree(evidence_dir, errors)

    expected_files = set()

    for entry in entries:
        if not isinstance(entry, dict):
            errors.append("Invalid evidence file entry in manifest.")
            continue

        relative_name = entry.get("path")

        if not isinstance(relative_name, str):
            errors.append("Evidence file path must be a string.")
            continue

        relative_path = PurePosixPath(relative_name)

        if (
            relative_path.is_absolute()
            or not relative_path.parts
            or ".." in relative_path.parts
            or "\\" in relative_name
            or relative_path.as_posix() != relative_name
            or relative_name in expected_files
        ):
            errors.append(f"Unsafe or duplicate evidence path: {relative_name}")
            continue

        expected_files.add(relative_name)

        expected_hash = entry.get("sha256")
        expected_size = entry.get("size_bytes")

        if (
            not isinstance(expected_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
        ):
            errors.append(f"Invalid SHA-256 value: {relative_name}")
            continue

        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
        ):
            errors.append(f"Invalid file size: {relative_name}")
            continue

        if relative_name not in actual_files:
            errors.append(f"Missing or unsafe evidence file: {relative_name}")
            continue

        evidence_file = evidence_dir.joinpath(*relative_path.parts)

        try:
            descriptor = os.open(
                evidence_file,
                os.O_RDONLY | os.O_NOFOLLOW,
            )

            try:
                file_stat = os.fstat(descriptor)

                if not stat.S_ISREG(file_stat.st_mode):
                    raise ValueError("Evidence entry is not a regular file.")

                digest = hashlib.sha256()
                actual_size = 0

                with os.fdopen(descriptor, "rb") as file:
                    descriptor = -1

                    for chunk in iter(
                        lambda: file.read(1024 * 1024),
                        b"",
                    ):
                        digest.update(chunk)
                        actual_size += len(chunk)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

        except (OSError, ValueError) as exc:
            errors.append(f"Could not safely read {relative_name}: {exc}")
            continue

        checked_files += 1

        if digest.hexdigest() != expected_hash:
            errors.append(f"SHA-256 mismatch: {relative_name}")

        if actual_size != expected_size:
            errors.append(f"File size mismatch: {relative_name}")

    for unexpected in sorted(actual_files - expected_files):
        errors.append(f"Unexpected evidence file: {unexpected}")

    for missing in sorted(expected_files - actual_files):
        message = f"Evidence file missing from package: {missing}"
        if message not in errors:
            errors.append(message)

    if not errors and "collection.json" in actual_files:
        try:
            validate_collection_directory(evidence_dir)
        except Exception as exc:
            errors.append(f"Collection validation failed: {exc}")

    return {
        "valid": not errors,
        "checked_files": checked_files,
        "errors": errors,
    }
