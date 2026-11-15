# OpenSanitize Evidence (OSE)

**Open-source evidence collection, integrity, and verification for storage sanitization audits.**

OpenSanitize Evidence (OSE) is an open-source toolkit designed to collect, preserve, authenticate, package, and independently verify evidence generated during storage-device sanitization activities.

OSE provides an evidence and audit layer around existing storage utilities. It does not perform disk erasure or sanitization itself.

## Project objectives

OSE aims to provide:

- Structured collection of storage-device identification and sanitization evidence.
- Preservation of original command output and error output.
- Recording of command arguments, execution times, exit codes, and utility versions.
- SHA-256 hashing of collected evidence.
- Canonical JSON evidence manifests.
- Ed25519 digital signatures for evidence manifests.
- Evidence package creation and independent integrity verification.
- A foundation for standardized sanitization audit reports.

## Scope and security boundary

OSE is an evidence management and verification project, not a disk sanitization engine.

It is designed to work alongside established utilities, including:

- openSeaChest
- smartmontools (`smartctl`)
- `hdparm`
- `nvme-cli`
- `sg3_utils`

The project does not independently guarantee that a storage device has been successfully sanitized.

A successful command, device-reported status, SMART health result, valid digital signature, or matching evidence hash must not individually be interpreted as proof of successful sanitization.

OSE distinguishes between:

1. **Evidence integrity:** whether collected files match their recorded cryptographic hashes.
2. **Evidence authenticity:** whether the manifest signature validates against the supplied public key.
3. **Sanitization assessment:** whether the available evidence supports the claimed sanitization outcome under the applicable policy and verification requirements.

These are separate assessments.

## Current implementation

The current prototype includes:

| Component | Function |
|---|---|
| Cryptographic module | SHA-256 hashing and Ed25519 signatures |
| Evidence packager | Creates signed evidence packages |
| Evidence verifier | Checks signatures, hashes, file sizes, and package contents |
| CLI | Provides key generation, packaging, and verification commands |
| openSeaChest collector | Performs read-only device discovery and evidence collection |
| Automated tests | Tests cryptography, packaging, verification, and collector behavior |

The openSeaChest collector currently records:

- Initial and final device inventory.
- Device identity information.
- openSeaChest version information.
- USB device scan output.
- Device information output.
- ATA/SAT identification output.
- Standard output and standard error as original binary files.
- Command execution metadata and evidence hashes.
- Collection status and identity consistency checks.

The current collector does not issue erase or sanitize commands.

## Architecture

The intended evidence workflow is:

1. Identify and validate the target storage device.
2. Collect evidence using supported utility adapters.
3. Preserve original command output and execution metadata.
4. Calculate SHA-256 hashes.
5. Generate a canonical JSON manifest.
6. Sign the manifest using Ed25519.
7. Package the evidence and signature.
8. Verify package integrity independently.
9. Generate an audit report based on the evidence and applicable sanitization policy.

## Requirements

- Linux environment
- Python 3.10 or newer
- Git
- Supported storage utilities for the relevant collectors
- `cryptography`
- `pytest` for development and testing

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd opensanitize-evidence
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project and development dependencies:

```bash
python -m pip install -e ".[dev]"
```

## Command-line interface

Generate an Ed25519 signing key pair:

```bash
ose keygen \
    --private keys/ose-signing-private.pem \
    --public keys/ose-signing-public.pem
```

Create a signed evidence package:

```bash
ose package \
    --input evidence/source \
    --output evidence/packages/example \
    --key keys/ose-signing-private.pem
```

Verify an evidence package:

```bash
ose verify \
    --input evidence/packages/example \
    --public-key keys/ose-signing-public.pem
```

A successful verification indicates that the package contents match the signed manifest and that its signature validates against the supplied public key. It does not establish that sanitization succeeded.

## Testing

Run the automated test suite:

```bash
python -m pytest -v
```

The current test suite covers:

- SHA-256 hashing.
- Ed25519 key generation and signature validation.
- Evidence package creation.
- Evidence integrity verification.
- Detection of modified, missing, and unexpected files.
- openSeaChest collector behavior.
- Collector failure and incomplete-evidence handling.

## Evidence and key management

Evidence packages and signing keys should be handled as sensitive audit artifacts.

Recommended practices:

- Never commit private signing keys to source control.
- Keep signing keys separate from collected evidence.
- Restrict private-key access.
- Maintain independently protected public-key copies.
- Preserve original evidence files.
- Retain evidence packages in access-controlled storage.
- Use trusted timestamps and immutable storage for stronger long-term assurance.

The current prototype uses local Ed25519 PEM keys. Production deployment requires additional key custody, timestamping, and operational security controls.

## Standards and audit context

OSE is intended to support evidence management for storage sanitization programs informed by:

**NIST Special Publication 800-88 Revision 2 — Guidelines for Media Sanitization.**

OSE does not claim certification, compliance, or conformance merely by collecting or verifying evidence. Sanitization decisions must be based on the applicable policy, technique, device capabilities, verification, validation, and documented review.

## Development roadmap

Planned development areas:

- [ ] Complete project documentation.
- [ ] Expand device discovery and identity normalization.
- [ ] Implement a dedicated smartctl collector.
- [ ] Implement hdparm evidence collection.
- [ ] Implement NVMe evidence collection.
- [ ] Implement SCSI evidence collection.
- [ ] Standardize evidence schemas across collectors.
- [ ] Improve atomic package creation and filesystem safety.
- [ ] Add trusted timestamp support.
- [ ] Add key-management improvements.
- [ ] Implement audit report and certificate generation.
- [ ] Develop an independent audit review interface.
- [ ] Add a web-based management dashboard.

## Project status

**Early development / prototype.**

The current implementation is intended for development, testing, and evaluation. It has not undergone an independent security audit and should not yet be treated as a production sanitization certification system.

## License

License to be determined.
