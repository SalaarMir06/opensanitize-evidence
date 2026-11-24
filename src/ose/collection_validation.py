"""Validation of Schema 2.0 collection directories."""

import json
from pathlib import Path, PurePosixPath

from ose.crypto import sha256_file
from ose.evidence_schema import validate_manifest


def validate_collection_directory(collection_dir):
    """Validate collection.json and its complete on-disk artifact set.

    Returns the parsed manifest on success.

    The collection manifest itself is excluded from its declared artifact
    set. Every other regular file must be declared by the manifest.
    """
    root = Path(collection_dir)

    if root.is_symlink() or not root.is_dir():
        raise ValueError("Collection path is not a regular directory")

    root = root.resolve(strict=True)
    manifest_path = root / "collection.json"

    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Collection manifest is missing or unsafe")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"Could not read collection manifest: {exc}") from exc

    errors = validate_manifest(manifest)

    if errors:
        raise ValueError(
            "Invalid OSE Evidence Schema 2.0 manifest:\\n- "
            + "\\n- ".join(errors)
        )

    expected_files = {}
    expected_directories = set()

    for artifact in manifest["artifacts"]:
        relative_name = artifact["path"]

        if relative_name == "collection.json":
            raise ValueError(
                "Artifact path cannot refer to collection.json"
            )

        relative_path = PurePosixPath(relative_name)
        expected_files[relative_name] = artifact

        for parent in relative_path.parents:
            if str(parent) != ".":
                expected_directories.add(parent.as_posix())

        artifact_path = root.joinpath(*relative_path.parts)

        current = root
        for part in relative_path.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError(
                    f"Symbolic link in collection artifact path: "
                    f"{relative_name}"
                )

        try:
            resolved = artifact_path.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"Missing or unsafe collection artifact: {relative_name}"
            ) from exc

        if not resolved.is_file():
            raise ValueError(
                f"Collection artifact is not a regular file: {relative_name}"
            )

        if resolved.stat().st_size != artifact["size_bytes"]:
            raise ValueError(
                f"Collection artifact size mismatch: {relative_name}"
            )

        if sha256_file(resolved) != artifact["hash"]["value"]:
            raise ValueError(
                f"Collection artifact SHA-256 mismatch: {relative_name}"
            )

    actual_files = set()
    actual_directories = set()

    for item in root.rglob("*"):
        relative_name = item.relative_to(root).as_posix()

        if item.is_symlink():
            raise ValueError(
                f"Symbolic link found in collection directory: {relative_name}"
            )

        if item.is_dir():
            actual_directories.add(relative_name)
        elif item.is_file():
            if relative_name != "collection.json":
                actual_files.add(relative_name)
        else:
            raise ValueError(
                f"Non-regular entry found in collection directory: "
                f"{relative_name}"
            )

    unexpected_files = sorted(actual_files - set(expected_files))
    missing_files = sorted(set(expected_files) - actual_files)
    unexpected_directories = sorted(
        actual_directories - expected_directories
    )

    if unexpected_files:
        raise ValueError(
            "Unexpected collection files: " + ", ".join(unexpected_files)
        )

    if missing_files:
        raise ValueError(
            "Missing collection files: " + ", ".join(missing_files)
        )

    if unexpected_directories:
        raise ValueError(
            "Unlisted collection directories: "
            + ", ".join(unexpected_directories)
        )

    return manifest
