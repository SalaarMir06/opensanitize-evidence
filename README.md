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

It is designed to work alongside established storage utilities, including:

- openSeaChest
- smartmontools (`smartctl`)
- `hdparm`
- `nvme-cli` (planned collector)
- `sg3_utils` (planned collector)

The project does not independently guarantee that a storage device has been successfully sanitized.

A successful command, device-reported status, SMART health result, valid digital signature, or matching evidence hash must not individually be interpreted as proof of successful sanitization.

OSE distinguishes between:

1. **Evidence integrity:** whether collected files match their recorded cryptographic hashes.
2. **Evidence authenticity:** whether the manifest signature validates against the supplied public key.
3. **Sanitization assessment:** whether the available evidence supports the claimed sanitization outcome under the applicable policy and verification requirements.

These are separate assessments. Cryptographic verification establishes properties of the evidence package, not the physical state of a storage device.

## Current implementation

The current prototype includes:

| Component | Function |
|---|---|
| Cryptographic module | SHA-256 hashing and Ed25519 signatures |
| Evidence packager | Creates signed evidence packages |
| Evidence verifier | Checks signatures, hashes, file sizes, package contents, and embedded Evidence Schema 2.0 collections |
| PDF report generator | Produces audit reports containing integrity results, evidence inventories, and sanitization assessment findings |
| CLI | Provides key generation, packaging, verification, and PDF reporting commands |
| openSeaChest collector | Performs read-only device discovery and evidence collection |
| smartctl collector | Captures device identity and diagnostic evidence using smartctl |
| hdparm collector | Captures ATA device identification and diagnostic evidence using hdparm |
| Automated tests | Tests cryptography, packaging, verification, assessment, reporting, and collector behavior |

### Evidence collectors

The current openSeaChest, smartctl, and hdparm collectors use the standardized Evidence Schema 2.0.

Their command coverage differs:

| Collector | Captured command evidence |
|---|---|
| openSeaChest | Utility version, USB device scan, device information, and SAT information |
| smartctl | Utility version, device scan, device information, and full device information |
| hdparm | Utility version and ATA IDENTIFY information |

The collectors also provide:

- Initial and final device inventory.
- Device identity information and identity consistency checks.
- Original standard output and standard error as binary evidence artifacts.
- Command arguments, execution metadata, exit codes, and artifact hashes.
- Collection status and incomplete-collection handling.

The collectors are separate Python entry points under `collectors/`. They are not currently exposed as subcommands of the installed `ose` CLI.

The current collectors perform read-only discovery and evidence collection. They do not issue erase, sanitize, security, or write commands.

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

- Linux environment.
- Python 3.10 or newer.
- Git.
- Supported storage utilities for the relevant collectors.
- `cryptography`.
- `jsonschema`.
- `reportlab`.
- `pytest` for development and testing.

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

The installed `ose` command currently provides four operations.

### Generate an Ed25519 signing key pair

```bash
ose keygen \
    --private keys/ose-signing-private.pem \
    --public keys/ose-signing-public.pem
```

The private key is written with restrictive file permissions on supported POSIX filesystems. The CLI refuses to overwrite existing key files.

Protect the private key carefully. Do not commit it to source control.

### Create a signed evidence package

```bash
ose package \
    --input evidence/source \
    --output evidence/packages/example \
    --key keys/ose-signing-private.pem
```

### Verify an evidence package

```bash
ose verify \
    --input evidence/packages/example \
    --public-key keys/ose-signing-public.pem
```

### Generate a PDF audit report

```bash
ose report \
    --input evidence/packages/example \
    --public-key keys/ose-signing-public.pem \
    --output reports/example-audit.pdf
```

An optional JSON file can provide separately documented sanitization operation evidence:

```bash
ose report \
    --input evidence/packages/example \
    --public-key keys/ose-signing-public.pem \
    --output reports/example-audit.pdf \
    --operation operation.json
```

The operation JSON must contain an object using the assessment engine's input fields. For example:

```json
{
  "status": "COMPLETED",
  "technique": "PURGE",
  "verification": {"status": "PASSED"},
  "validation": {"status": "PASSED"}
}
```

This operation evidence is supplied separately; it is not added to the signed evidence package.

A generic package without an Evidence Schema 2.0 collection remains `NOT_ASSESSED`. A Schema 2.0 collection with sufficient operation evidence may reach `UNDER_REVIEW`, but the current assessment engine does not issue `CONFORMANT` conclusions.

### Report command exit codes

- `0`: PDF generated and package integrity verification passed.
- `1`: PDF generated, but package integrity verification failed. The report does not assess untrusted embedded evidence.
- `2`: Report generation or input processing failed.

A successful package verification indicates that the package contents match the signed manifest and that its signature validates against the supplied public key.

It does not establish that sanitization succeeded. A valid signature establishes integrity relative to the signing key, not physical erasure.

## Testing

Run the automated test suite:

```bash
python -m pytest -v
```

The test suite covers:

- SHA-256 hashing.
- Ed25519 key generation and signature validation.
- Evidence package creation.
- Evidence integrity verification and tamper detection.
- Manifest structure and strict JSON validation.
- Evidence Schema 2.0 validation and collection artifact integrity.
- Deterministic sanitization assessment behavior.
- PDF report generation and CLI behavior.
- openSeaChest, smartctl, and hdparm collector behavior.
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

The verifier includes protections against symbolic links and special filesystem entries. However, it is not yet designed to eliminate every race condition involving concurrent filesystem modification or path replacement. Verify packages in a controlled environment and avoid modifying them during verification.

## Standards and audit context

OSE is intended to support evidence management for storage sanitization programs informed by:

**NIST Special Publication 800-88 Revision 2 — Guidelines for Media Sanitization.**

OSE does not claim certification, compliance, or conformance merely by collecting or verifying evidence. Sanitization decisions must be based on the applicable policy, technique, device capabilities, verification, validation, and documented review.

## Development roadmap

Planned development areas:

- [x] Implement the initial evidence collection and packaging architecture.
- [x] Implement openSeaChest, smartctl, and hdparm collectors.
- [x] Standardize evidence schemas across collectors (Evidence Schema 2.0).
- [x] Implement atomic evidence package creation.
- [x] Implement baseline filesystem safety and package verification controls.
- [x] Implement deterministic sanitization assessment.
- [x] Implement PDF audit report generation.
- [x] Implement CLI key generation, packaging, verification, and reporting.
- [x] Add automated regression tests for core workflows.
- [ ] Expand device discovery and identity normalization.
- [ ] Implement NVMe evidence collection.
- [ ] Implement SCSI evidence collection.
- [ ] Add trusted timestamp support.
- [ ] Improve signing-key management and custody.
- [ ] Develop formal certificate issuance and approval workflows.
- [ ] Develop an independent audit review interface.
- [ ] Add a web-based management dashboard.
- [ ] Complete release documentation and independent security review.

## Project status

**Early development / prototype.**

The current implementation is intended for development, testing, and evaluation. It has not undergone an independent security audit and should not yet be treated as a production sanitization certification system.

## License

OpenSanitize Evidence is licensed under the **Apache License, Version 2.0**.

See [LICENSE](LICENSE) for the full licence text.

Unless required by applicable law or agreed to in writing, software distributed under this licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
