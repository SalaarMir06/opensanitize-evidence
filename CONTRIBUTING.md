# Contributing to OpenSanitize Evidence (OSE)

Thank you for your interest in contributing to OpenSanitize Evidence.

OSE is an open-source toolkit for collecting, preserving, authenticating, packaging, reporting, and verifying disk sanitization evidence.

Contributions are welcome, including bug fixes, security improvements, tests, documentation, and new evidence collectors.

## 1. Project principles

All contributions must respect these principles:

- OSE collects and evaluates sanitization evidence; it does not perform disk sanitization.
- Original evidence must be preserved without modification.
- Evidence integrity and authenticity must be verifiable.
- Cryptographic signatures establish integrity and provenance, not proof of physical erasure.
- Audit conclusions must not exceed what the available evidence supports.
- Destructive device operations must not be introduced without explicit project approval.

## 2. Ways to contribute

You can contribute by:

- Reporting bugs and suggesting improvements.
- Adding or improving evidence collectors.
- Improving cryptographic verification.
- Writing unit and integration tests.
- Improving documentation and examples.
- Improving compatibility across supported Python versions.

## 3. Development environment

OSE requires Python 3.10 or later.

Fork the repository on GitHub, then clone your fork:

    git clone https://github.com/YOUR_USERNAME/opensanitize-evidence.git
    cd opensanitize-evidence

Create and activate a virtual environment:

    python -m venv .venv
    source .venv/bin/activate

Install the project and development dependencies:

    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"

## 4. Create a contribution branch

Create a separate branch for your changes:

    git checkout -b feature/your-change

Examples:

- feature/nvme-collector
- fix/manifest-validation
- tests/verifier-edge-cases
- docs/installation-guide

## 5. Code and testing requirements

Before submitting a pull request:

- Keep changes focused and maintainable.
- Add or update tests for changed behaviour.
- Do not commit private keys, credentials, personal data, or sensitive device information.
- Do not include real sanitization evidence containing sensitive information.
- Preserve backward compatibility where practical.
- Update documentation when behaviour or CLI options change.

Run the test suite:

    PYTHONPATH="$PWD:$PWD/src" pytest

Check Python syntax:

    python -m compileall -q src collectors tests

Check patch formatting:

    git diff --check

All tests should pass before submitting a pull request.

## 6. Commit your changes

Use clear commit messages describing your changes:

    git add .
    git commit -m "Add NVMe evidence collector"

Avoid committing generated files, virtual environments, build artifacts, or unrelated changes.

## 7. Submit a pull request

Push your branch:

    git push -u origin feature/your-change

Open a pull request against the project's main branch.

A pull request should include:

- A clear description of the problem or proposed improvement.
- The changes made and their purpose.
- Tests performed and their results.
- Relevant documentation updates.
- Compatibility considerations.

GitHub Actions runs the automated test suite against supported Python versions. Pull requests may require changes before they can be merged.

## 8. Evidence collector contributions

New collectors should:

- Capture the exact command and arguments used.
- Record tool name and version where available.
- Preserve standard output and standard error.
- Record timestamps and exit status.
- Capture device identity and relevant operation details.
- Preserve warnings and errors.
- Avoid modifying original evidence.
- Distinguish device-reported status from independently verified results.

A successful command exit code or device health indicator alone must not be interpreted as proof of successful sanitization.

## 9. Security-related contributions

Security vulnerabilities should be reported privately using the process described in SECURITY.md, rather than disclosed publicly in an issue.

Do not submit real private keys, credentials, personal information, or confidential device records.

## 10. License

By submitting a contribution, you agree that your contributions will be licensed under the project's Apache License 2.0.

Thank you for helping improve OpenSanitize Evidence.
