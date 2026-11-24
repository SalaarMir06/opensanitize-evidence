import argparse
import json
import sys
from pathlib import Path

from ose.crypto import generate_key_pair
from ose.packager import create_package
from ose.report import generate_report
from ose.verifier import verify_package


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ose",
        description="OpenSanitize Evidence - evidence integrity toolkit",
    )

    commands = parser.add_subparsers(dest="command", required=True)

    # Key generation command
    keygen = commands.add_parser(
        "keygen",
        help="Generate an Ed25519 signing key pair",
    )
    keygen.add_argument("--private", required=True, help="Private key output path")
    keygen.add_argument("--public", required=True, help="Public key output path")

    # Evidence packaging command
    package = commands.add_parser(
        "package",
        help="Create and sign an evidence package",
    )
    package.add_argument("--input", required=True, help="Source evidence directory")
    package.add_argument("--output", required=True, help="Package output directory")
    package.add_argument("--key", required=True, help="Private signing key")
    package.add_argument("--metadata", help="Optional JSON metadata file")

    # Verification command
    verify = commands.add_parser(
        "verify",
        help="Verify an evidence package",
    )
    verify.add_argument("--input", required=True, help="Evidence package directory")
    verify.add_argument("--public-key", required=True, help="Public verification key")

    # PDF audit report command
    report = commands.add_parser(
        "report",
        help="Generate a PDF audit report from an evidence package",
    )
    report.add_argument("--input", required=True, help="Evidence package directory")
    report.add_argument("--public-key", required=True, help="Public verification key")
    report.add_argument("--output", required=True, help="PDF report output path")
    report.add_argument(
        "--operation",
        help="Optional JSON file containing separately supplied operation evidence",
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "keygen":
            private_path = Path(args.private)
            public_path = Path(args.public)

            if private_path.resolve() == public_path.resolve():
                raise ValueError("Private and public key paths must be different.")

            if private_path.exists() or public_path.exists():
                raise FileExistsError(
                    "A key file already exists. Choose new paths; "
                    "existing keys will not be overwritten."
                )

            generate_key_pair(private_path, public_path)

            print("Ed25519 key pair generated.")
            print(f"Private key: {private_path}")
            print(f"Public key:  {public_path}")

        elif args.command == "package":
            metadata = {}

            if args.metadata:
                metadata_path = Path(args.metadata)
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

                if not isinstance(metadata, dict):
                    raise ValueError("Metadata JSON must contain an object.")

            manifest = create_package(
                evidence_dir=args.input,
                output_dir=args.output,
                private_key_path=args.key,
                metadata=metadata,
            )

            print("Evidence package created.")
            print(f"Package ID: {manifest['package_id']}")
            print(f"Evidence files: {len(manifest['evidence_files'])}")
            print(f"Output: {Path(args.output).resolve()}")

        elif args.command == "verify":
            result = verify_package(args.input, args.public_key)

            print(json.dumps(result, indent=2))

            if result["valid"]:
                print("INTEGRITY CHECK: PASSED")
                return 0

            print("INTEGRITY CHECK: FAILED")
            return 1

        elif args.command == "report":
            operation = None

            if args.operation:
                operation_path = Path(args.operation)
                operation = json.loads(
                    operation_path.read_text(encoding="utf-8")
                )

                if not isinstance(operation, dict):
                    raise ValueError(
                        "Operation evidence JSON must contain an object."
                    )

            result = generate_report(
                package_dir=args.input,
                public_key_path=args.public_key,
                output_path=args.output,
                operation=operation,
            )

            print(json.dumps(result, indent=2))
            print(f"PDF REPORT: {result['output_path']}")

            if result["integrity_valid"]:
                print("INTEGRITY CHECK: PASSED")
                return 0

            print("INTEGRITY CHECK: FAILED")
            return 1

    except (OSError, ValueError, TypeError, FileExistsError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
