
# Security Policy

## Supported Versions

Security updates are currently provided for the latest development version on the `main` branch.

Older releases may not receive security fixes. Users should upgrade to the latest supported version where practical.

## Reporting a Vulnerability

If you discover a potential security vulnerability in OpenSanitize Evidence (OSE), please report it privately.

**Do not disclose vulnerabilities through public GitHub issues or pull requests.**

Use GitHub's private vulnerability reporting feature:

https://github.com/SalaarMir06/opensanitize-evidence/security/advisories/new

If private vulnerability reporting is unavailable, contact the repository maintainer through their GitHub profile:

https://github.com/SalaarMir06

## What to Include

Please provide as much of the following information as possible:

- A description of the vulnerability.
- The affected component, file, or version.
- Steps to reproduce the issue.
- Potential security impact.
- Proof-of-concept code or logs, if safe to share.
- Any suggested mitigation.

Do not include real private keys, credentials, personal information, or confidential sanitization evidence in your report.

## Scope

Security reports relevant to OSE include, but are not limited to:

- Evidence tampering or integrity verification failures.
- Cryptographic signing or signature verification weaknesses.
- Manifest validation and parsing vulnerabilities.
- Path traversal and unsafe file handling.
- Unauthorized modification of evidence packages.
- Sensitive information disclosure.
- Unsafe handling of external command output.
- Vulnerabilities in PDF report generation.

## Project Security Boundaries

OSE is an evidence collection, integrity, reporting, and verification toolkit. It does not perform disk sanitization.

A valid cryptographic signature establishes evidence integrity and provenance relative to a signing key. It does not independently prove that a storage device was successfully sanitized.

Security assessments and audit conclusions must remain within the evidence available.

## Disclosure

Please allow the maintainer reasonable time to investigate and address a reported vulnerability before public disclosure.

The maintainer will assess the report, determine its impact, and work toward an appropriate fix.

Thank you for helping improve the security of OpenSanitize Evidence.
