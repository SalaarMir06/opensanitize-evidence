import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ose.crypto import sha256_file, sign_data
from ose.collection_validation import validate_collection_directory


def canonical_json(data: dict) -> bytes:
    """Serialize JSON consistently so the exact bytes can be signed."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def create_package(
    evidence_dir: str | Path,
    output_dir: str | Path,
    private_key_path: str | Path,
    metadata: dict | None = None,
) -> dict:
    """
    Copy evidence into a package, hash each copied file,
    create a manifest, and sign the manifest.

    The source evidence directory is not modified.
    """
    source = Path(evidence_dir).resolve()
    output = Path(output_dir).resolve()
    private_key = Path(private_key_path).resolve()

    if not source.is_dir():
        raise ValueError(f"Evidence directory does not exist: {source}")

    has_collection_manifest = (
        (source / "collection.json").exists()
        or (source / "collection.json").is_symlink()
    )

    if has_collection_manifest:
        validate_collection_directory(source)

    if output == source or source in output.parents:
        raise ValueError("Output directory cannot be inside the source directory.")

    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(
            f"Output directory must be empty or not exist: {output}"
        )

    if not private_key.is_file():
        raise FileNotFoundError(f"Private key not found: {private_key}")

    if metadata is None:
        metadata = {}

    if not isinstance(metadata, dict):
        raise TypeError("Metadata must be a dictionary.")

    # Validate that metadata can be represented as JSON.
    canonical_json(metadata)

    output.mkdir(parents=True, exist_ok=True)
    package_evidence = output / "evidence"
    package_evidence.mkdir()

    evidence_files = []

    # Copy regular files only. Reject symbolic links to avoid collecting
    # files from unexpected locations.
    for item in sorted(source.rglob("*")):
        if item.is_symlink():
            raise ValueError(f"Symbolic links are not permitted: {item}")

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

    (output / "manifest.json").write_bytes(manifest_bytes)
    (output / "manifest.sig").write_text(
        signature + "\n",
        encoding="ascii",
    )

    return manifest
