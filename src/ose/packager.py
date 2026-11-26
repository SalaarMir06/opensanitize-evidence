import ctypes
import errno
import json
import os
import shutil
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ose.crypto import sha256_file, sign_data
from ose.collection_validation import validate_collection_directory


AT_FDCWD = -100
RENAME_NOREPLACE = 1


def canonical_json(data: dict) -> bytes:
    """Serialize JSON consistently so the exact bytes can be signed."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _rename_directory_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing any destination."""
    if sys.platform != "linux":
        raise OSError(
            errno.ENOTSUP,
            "Secure atomic package publication currently requires Linux.",
        )

    libc = ctypes.CDLL(None, use_errno=True)

    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise OSError(
            errno.ENOTSUP,
            "The system does not expose renameat2.",
        ) from exc

    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int

    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )

    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(
            error_number,
            os.strerror(error_number),
            str(destination),
        )


def _fsync_file(path: Path) -> None:
    """Flush a regular file's contents to the filesystem."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)

    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"Package entry is not a regular file: {path}")

        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    """Flush directory metadata to the filesystem."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)

    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_package_tree(root: Path) -> None:
    """Flush all package files and directories, bottom-up."""
    directories = []

    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories.append(current_path)

        for filename in filenames:
            _fsync_file(current_path / filename)

        for dirname in dirnames:
            child = current_path / dirname
            if child.is_symlink():
                raise ValueError(
                    f"Symbolic links are not permitted: {child}"
                )

    for directory in reversed(directories):
        _fsync_directory(directory)


def create_package(
    evidence_dir: str | Path,
    output_dir: str | Path,
    private_key_path: str | Path,
    metadata: dict | None = None,
) -> dict:
    """
    Build, validate, sign and atomically publish an evidence package.

    The source evidence directory is not modified. The final destination
    is never exposed until the complete package has been signed.
    """
    source_candidate = Path(evidence_dir).expanduser()
    if source_candidate.is_symlink():
        raise ValueError("Evidence directory cannot be a symbolic link.")
    source = source_candidate.resolve()
    output_candidate = Path(output_dir).expanduser()

    if not output_candidate.name:
        raise ValueError("Output directory must have a directory name.")

    output_parent = output_candidate.parent.resolve()
    output = output_parent / output_candidate.name
    private_key = Path(private_key_path).resolve()

    if not source.is_dir():
        raise ValueError(f"Evidence directory does not exist: {source}")

    if output == source or source in output.parents:
        raise ValueError(
            "Output directory cannot be inside the source directory."
        )

    if not private_key.is_file():
        raise FileNotFoundError(f"Private key not found: {private_key}")

    if metadata is None:
        metadata = {}

    if not isinstance(metadata, dict):
        raise TypeError("Metadata must be a dictionary.")

    # Validate that metadata can be represented as JSON.
    canonical_json(metadata)

    has_collection_manifest = (
        (source / "collection.json").exists()
        or (source / "collection.json").is_symlink()
    )

    if has_collection_manifest:
        validate_collection_directory(source)

    output_parent.mkdir(parents=True, exist_ok=True)

    # Staging and destination must be on the same filesystem.
    staging_name = tempfile.mkdtemp(
        prefix=f".{output.name}.staging-",
        dir=output_parent,
    )
    staging = Path(staging_name)

    try:
        package_evidence = staging / "evidence"
        package_evidence.mkdir()

        evidence_files = []

        # Copy regular files only. Reject symbolic links to avoid
        # collecting files from unexpected locations.
        for item in sorted(source.rglob("*")):
            if item.is_symlink():
                raise ValueError(
                    f"Symbolic links are not permitted: {item}"
                )

            if not item.is_file():
                continue

            relative_path = item.relative_to(source)
            destination = package_evidence / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)

            shutil.copy2(item, destination)

            evidence_files.append({
                "path": relative_path.as_posix(),
                "size_bytes": destination.stat().st_size,
                "sha256": sha256_file(destination),
            })

        # Validate the copied snapshot, not just the original source.
        if has_collection_manifest:
            validate_collection_directory(package_evidence)

        manifest = {
            "schema_version": "1.0",
            "package_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hash_algorithm": "SHA-256",
            "signature_algorithm": "Ed25519",
            "evidence_files": evidence_files,
            "metadata": metadata,
        }

        manifest_bytes = canonical_json(manifest)
        signature = sign_data(manifest_bytes, private_key)

        manifest_path = staging / "manifest.json"
        with manifest_path.open("xb") as file:
            file.write(manifest_bytes)
            file.flush()
            os.fsync(file.fileno())

        signature_path = staging / "manifest.sig"
        with signature_path.open("xb") as file:
            file.write((signature + "\n").encode("ascii"))
            file.flush()
            os.fsync(file.fileno())

        # Flush copied evidence and directory metadata before publication.
        _fsync_package_tree(staging)

        # Atomic no-replace publication. Existing destinations, including
        # empty directories and symlinks, cause this operation to fail.
        _rename_directory_noreplace(staging, output)

        # Persist the directory entry created by the rename.
        _fsync_directory(output_parent)

        return manifest

    finally:
        # On pre-publication failure, remove the incomplete staging tree.
        # After successful publication, staging no longer exists.
        if staging.exists():
            shutil.rmtree(staging)
