import hashlib

from ose.crypto import (
    generate_key_pair,
    sha256_file,
    sign_data,
    verify_signature,
)


def test_sha256_file(tmp_path):
    evidence_file = tmp_path / "sample.log"
    evidence_file.write_bytes(b"OpenSanitize Evidence test")

    expected = hashlib.sha256(
        b"OpenSanitize Evidence test"
    ).hexdigest()

    assert sha256_file(evidence_file) == expected


def test_key_generation(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)

    assert private_key.exists()
    assert public_key.exists()

    # Private signing key must not be readable by group or others.
    assert private_key.stat().st_mode & 0o077 == 0


def test_valid_signature(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)

    message = b"Test evidence manifest"
    signature = sign_data(message, private_key)

    assert verify_signature(message, signature, public_key)


def test_modified_message_is_rejected(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)

    message = b"Original evidence manifest"
    signature = sign_data(message, private_key)

    assert not verify_signature(
        b"Modified evidence manifest",
        signature,
        public_key,
    )


def test_modified_signature_is_rejected(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)

    message = b"Test evidence manifest"
    signature = sign_data(message, private_key)

    assert not verify_signature(
        message,
        signature[:-4] + "AAAA",
        public_key,
    )


def test_valid_signature_with_public_key_bytes(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)

    message = b"Test evidence manifest"
    signature = sign_data(message, private_key)
    public_key_bytes = public_key.read_bytes()

    assert verify_signature(message, signature, public_key_bytes)
