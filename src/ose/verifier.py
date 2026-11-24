import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from ose.crypto import verify_signature
from ose.collection_validation import validate_collection_directory


def verify_package(
    package_dir: str | Path,
    public_key_path: str | Path,
) -> dict:
    """
    Verify an evidence package's manifest signature and file integrity.

    This verifies integrity, not whether sanitization succeeded.
    """
    package = Path(package_dir).resolve()
    public_key = Path(public_key_path)

    errors = []
    checked_files = 0

    manifest_path = package / "manifest.json"
    signature_path = package / "manifest.sig"
    evidence_dir = package / "evidence"

    if not package.is_dir():
        return {
            "valid": False,
            "checked_files": 0,
            "errors": ["Package directory does not exist."],
        }

    if not manifest_path.is_file() or not signature_path.is_file():
        return {
            "valid": False,
            "checked_files": 0,
            "errors": ["Manifest or signature file is missing."],
        }

    if not public_key.is_file():
        return {
            "valid": False,
            "checked_files": 0,
            "errors": ["Public key file does not exist."],
        }

    try:
        manifest_bytes = manifest_path.read_bytes()
        signature = signature_path.read_text(encoding="ascii").strip()

        if not verify_signature(
            manifest_bytes,
            signature,
            public_key,
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

    if not isinstance(manifest.get("evidence_files"), list):
        errors.append("Manifest evidence_files must be a list.")
        entries = []
    else:
        entries = manifest["evidence_files"]

    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        errors.append("Evidence directory is missing or is a symbolic link.")
        actual_files = set()
    else:
        actual_files = set()

        for item in evidence_dir.rglob("*"):
            if item.is_symlink():
                errors.append(
                    f"Symbolic link found in evidence directory: {item}"
                )
            elif item.is_file():
                actual_files.add(item.relative_to(evidence_dir).as_posix())

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
            or relative_name in expected_files
        ):
            errors.append(f"Unsafe or duplicate evidence path: {relative_name}")
            continue

        expected_files.add(relative_name)
        evidence_file = evidence_dir.joinpath(*relative_path.parts)

        try:
            resolved = evidence_file.resolve(strict=True)
            resolved.relative_to(evidence_dir.resolve(strict=True))
        except (OSError, ValueError):
            errors.append(f"Missing or unsafe evidence file: {relative_name}")
            continue

        if evidence_file.is_symlink() or not resolved.is_file():
            errors.append(f"Evidence entry is not a regular file: {relative_name}")
            continue

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

        digest = hashlib.sha256()
        actual_size = 0

        try:
            with resolved.open("rb") as file:
                for chunk in iter(lambda: file.read(1024 * 1024), b""):
                    digest.update(chunk)
                    actual_size += len(chunk)
        except OSError as exc:
            errors.append(f"Could not read {relative_name}: {exc}")
            continue

        checked_files += 1

        if digest.hexdigest() != expected_hash:
            errors.append(f"SHA-256 mismatch: {relative_name}")

        if actual_size != expected_size:
            errors.append(f"File size mismatch: {relative_name}")

    for unexpected in sorted(actual_files - expected_files):
        errors.append(f"Unexpected evidence file: {unexpected}")

    for missing in sorted(expected_files - actual_files):
        errors.append(f"Evidence file missing from package: {missing}")

    if (
        not errors
        and (evidence_dir / "collection.json").exists()
    ):
        try:
            validate_collection_directory(evidence_dir)
        except (OSError, ValueError) as exc:
            errors.append(f"Collection validation failed: {exc}")

    return {
        "valid": not errors,
        "checked_files": checked_files,
        "errors": errors,
    }
