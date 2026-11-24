import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sha256_file(file_path: str | Path) -> str:
    """Calculate the SHA-256 hash of a file without loading it all into memory."""
    digest = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def generate_key_pair(
    private_key_path: str | Path,
    public_key_path: str | Path,
) -> None:
    """Generate an Ed25519 key pair and save it in PEM format."""
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    private_path.chmod(0o600)
    public_path.write_bytes(public_bytes)
    public_path.chmod(0o644)


def sign_data(data: bytes, private_key_path: str | Path) -> str:
    """Sign bytes using an Ed25519 private key."""
    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(),
        password=None,
    )

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("The supplied key is not an Ed25519 private key.")

    signature = private_key.sign(data)
    return base64.b64encode(signature).decode("ascii")


def verify_signature(
    data: bytes,
    signature: str,
    public_key_path: str | Path | bytes,
) -> bool:
    """Verify an Ed25519 signature using a key path or PEM bytes."""
    if isinstance(public_key_path, bytes):
        public_key_bytes = public_key_path
    else:
        public_key_bytes = Path(public_key_path).read_bytes()

    public_key = serialization.load_pem_public_key(public_key_bytes)

    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("The supplied key is not an Ed25519 public key.")

    try:
        public_key.verify(base64.b64decode(signature, validate=True), data)
        return True
    except (InvalidSignature, ValueError):
        return False
