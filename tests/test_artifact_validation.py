import hashlib

import pytest

from collectors.openseachest.collector import (
    validate_output_artifacts as validate_openseachest,
)
from collectors.smartctl.collector import (
    validate_output_artifacts as validate_smartctl,
)
from collectors.hdparm.collector import (
    validate_output_artifacts as validate_hdparm,
)


VALIDATORS = [
    pytest.param(validate_openseachest, id="openseachest"),
    pytest.param(validate_smartctl, id="smartctl"),
    pytest.param(validate_hdparm, id="hdparm"),
]


def make_artifact(path, data):
    return {
        "artifact_id": "test-stdout",
        "role": "stdout",
        "path": path,
        "media_type": "application/octet-stream",
        "size_bytes": len(data),
        "hash": {
            "algorithm": "sha256",
            "value": hashlib.sha256(data).hexdigest(),
        },
    }


@pytest.mark.parametrize("validator", VALIDATORS)
def test_validator_accepts_valid_artifact(tmp_path, validator):
    output_dir = tmp_path / "collection"
    output_dir.mkdir()

    data = b"original evidence bytes"
    (output_dir / "stdout.bin").write_bytes(data)

    artifacts = [make_artifact("stdout.bin", data)]

    validator(output_dir, artifacts)


UNSAFE_PATHS = [
    "../escape.bin",
    "/tmp/escape.bin",
    "nested//file.bin",
    "nested/./file.bin",
    "C:/escape.bin",
    "bad\nname.bin",
    "bad\x7fname.bin",
]


@pytest.mark.parametrize("validator", VALIDATORS)
@pytest.mark.parametrize("unsafe_path", UNSAFE_PATHS)
def test_validator_rejects_unsafe_artifact_paths(
    tmp_path,
    validator,
    unsafe_path,
):
    output_dir = tmp_path / "collection"
    output_dir.mkdir()

    artifacts = [make_artifact(unsafe_path, b"")]

    with pytest.raises(ValueError, match="Unsafe artifact path"):
        validator(output_dir, artifacts)


@pytest.mark.parametrize("validator", VALIDATORS)
def test_validator_rejects_unlisted_file(tmp_path, validator):
    output_dir = tmp_path / "collection"
    output_dir.mkdir()

    data = b"declared evidence"
    (output_dir / "stdout.bin").write_bytes(data)
    (output_dir / "extra.bin").write_bytes(b"unlisted")

    artifacts = [make_artifact("stdout.bin", data)]

    with pytest.raises(ValueError):
        validator(output_dir, artifacts)


@pytest.mark.parametrize("validator", VALIDATORS)
def test_validator_rejects_unlisted_directory(tmp_path, validator):
    output_dir = tmp_path / "collection"
    output_dir.mkdir()

    data = b"declared evidence"
    (output_dir / "stdout.bin").write_bytes(data)
    (output_dir / "unexpected").mkdir()

    artifacts = [make_artifact("stdout.bin", data)]

    with pytest.raises(ValueError):
        validator(output_dir, artifacts)


@pytest.mark.parametrize("validator", VALIDATORS)
@pytest.mark.parametrize("mutation", ["size", "content"])
def test_validator_rejects_modified_artifact(
    tmp_path,
    validator,
    mutation,
):
    output_dir = tmp_path / "collection"
    output_dir.mkdir()

    original = b"original evidence"
    artifact_path = output_dir / "stdout.bin"
    artifact_path.write_bytes(original)

    artifacts = [make_artifact("stdout.bin", original)]

    if mutation == "size":
        artifact_path.write_bytes(b"changed size")
    else:
        artifact_path.write_bytes(b"changed content")

    with pytest.raises(ValueError):
        validator(output_dir, artifacts)


@pytest.mark.parametrize("validator", VALIDATORS)
def test_validator_rejects_symlink_artifact(tmp_path, validator):
    output_dir = tmp_path / "collection"
    output_dir.mkdir()

    outside_file = tmp_path / "outside.bin"
    outside_file.write_bytes(b"external evidence")

    link_path = output_dir / "stdout.bin"

    try:
        link_path.symlink_to(outside_file)
    except (NotImplementedError, OSError):
        pytest.skip("Symlinks are unavailable on this platform")

    artifacts = [make_artifact("stdout.bin", b"external evidence")]

    with pytest.raises(ValueError):
        validator(output_dir, artifacts)


@pytest.mark.parametrize("validator", VALIDATORS)
def test_validator_rejects_symlink_parent_directory(tmp_path, validator):
    output_dir = tmp_path / "collection"
    output_dir.mkdir()

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "stdout.bin").write_bytes(b"external evidence")

    try:
        (output_dir / "nested").symlink_to(
            outside_dir,
            target_is_directory=True,
        )
    except (NotImplementedError, OSError):
        pytest.skip("Symlinks are unavailable on this platform")

    artifacts = [
        make_artifact("nested/stdout.bin", b"external evidence")
    ]

    with pytest.raises(ValueError):
        validator(output_dir, artifacts)


@pytest.mark.parametrize("validator", VALIDATORS)
def test_validator_rejects_non_regular_artifact(tmp_path, validator):
    output_dir = tmp_path / "collection"
    output_dir.mkdir()

    (output_dir / "stdout.bin").mkdir()

    artifacts = [make_artifact("stdout.bin", b"")]

    with pytest.raises(ValueError):
        validator(output_dir, artifacts)
