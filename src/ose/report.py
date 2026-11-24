"""Generate PDF audit reports from verified OSE evidence packages."""

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ose.assessment import assess_collection
from ose.collection_validation import validate_collection_directory
from ose.verifier import verify_package


def _paragraph(value, style):
    """Create a safely escaped PDF paragraph."""
    return Paragraph(escape(str(value)), style)


def _key_value_table(rows, styles):
    """Build a two-column metadata table."""
    data = []

    for label, value in rows:
        data.append([
            _paragraph(label, styles["Label"]),
            _paragraph(value, styles["BodyText"]),
        ])

    table = Table(data, colWidths=[48 * mm, 122 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _section(title, styles):
    return [
        Spacer(1, 5 * mm),
        Paragraph(escape(title), styles["Heading2"]),
        HRFlowable(
            width="100%",
            thickness=0.6,
            color=colors.grey,
            spaceAfter=3 * mm,
        ),
    ]


def _page_footer(canvas, document):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(
        20 * mm,
        12 * mm,
        "OpenSanitize Evidence | Evidence integrity is not proof of sanitization.",
    )
    canvas.drawRightString(
        A4[0] - 20 * mm,
        12 * mm,
        f"Page {document.page}",
    )
    canvas.restoreState()


def generate_report(
    package_dir,
    public_key_path,
    output_path,
    operation=None,
):
    """Generate a PDF report from an evidence package.

    Package integrity is verified before any embedded evidence is trusted.

    If verification fails, a failure report is still generated, but no
    embedded manifest or sanitization assessment is used.

    `operation` is optional, separately supplied normalized sanitization
    operation evidence. It is never inferred from collector commands.

    Existing output files are not overwritten. The report cannot be
    written inside the evidence package.
    """
    package = Path(package_dir).resolve()
    public_key = Path(public_key_path).resolve()
    output_candidate = Path(output_path).expanduser().absolute()

    if not output_candidate.parent.is_dir():
        raise ValueError("Report output directory does not exist.")

    output = output_candidate.parent.resolve() / output_candidate.name

    if output.exists() or output.is_symlink():
        raise FileExistsError(f"Report output already exists: {output}")

    if output == package or package in output.parents:
        raise ValueError("Report output cannot be inside the evidence package.")

    # Verify the package before reading its embedded evidence.
    try:
        loaded_public_key = serialization.load_pem_public_key(
            public_key.read_bytes()
        )
        public_key_der = loaded_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_fingerprint = hashlib.sha256(
            public_key_der
        ).hexdigest()
    except (OSError, ValueError, TypeError):
        public_key_fingerprint = "UNAVAILABLE"

    try:
        integrity = verify_package(package, public_key)
    except (OSError, ValueError, TypeError) as exc:
        integrity = {
            "valid": False,
            "checked_files": 0,
            "errors": [
                f"Package verification could not be completed: {exc}"
            ],
        }

    package_manifest = None
    collection = None
    assessment = None

    if integrity["valid"]:
        manifest_path = package / "manifest.json"

        package_manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )

        collection_path = package / "evidence" / "collection.json"

        if collection_path.is_file():
            collection = validate_collection_directory(
                package / "evidence"
            )
            assessment = assess_collection(collection, operation)

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=19,
        leading=23,
        alignment=TA_CENTER,
        spaceAfter=5 * mm,
    ))

    styles.add(ParagraphStyle(
        name="Label",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
    ))

    styles["BodyText"].fontSize = 8
    styles["BodyText"].leading = 11
    styles["Heading2"].fontSize = 12
    styles["Heading2"].leading = 15

    story = [
        Paragraph("OpenSanitize Evidence", styles["ReportTitle"]),
        Paragraph(
            "Evidence Package Audit Report",
            ParagraphStyle(
                "Subtitle",
                parent=styles["Normal"],
                alignment=TA_CENTER,
                fontSize=11,
            ),
        ),
        Spacer(1, 3 * mm),
        HRFlowable(width="100%", thickness=1, color=colors.black),
        Spacer(1, 4 * mm),
    ]

    generated_at = datetime.now(timezone.utc).isoformat()

    story.extend(_section("Report information", styles))
    story.append(_key_value_table([
        ("Generated (UTC)", generated_at),
        ("Package directory", str(package)),
        ("Report format", "PDF"),
        ("Verification public key", str(public_key)),
        ("Public key DER SHA-256", public_key_fingerprint),
    ], styles))

    story.extend(_section("Package integrity verification", styles))

    integrity_status = "PASSED" if integrity["valid"] else "FAILED"

    story.append(_key_value_table([
        ("Integrity result", integrity_status),
        ("Files checked", integrity["checked_files"]),
        ("Signature and hash verification", integrity_status),
    ], styles))

    if not integrity["valid"]:
        story.extend(_section("Verification errors", styles))

        for error in integrity["errors"]:
            story.append(
                Paragraph(
                    "&#8226; " + escape(str(error)),
                    styles["BodyText"],
                )
            )
            story.append(Spacer(1, 1 * mm))

        story.extend(_section("Assessment limitation", styles))
        story.append(Paragraph(
            "The evidence package failed integrity verification. "
            "Embedded evidence was not used for sanitization assessment. "
            "No sanitization conclusion is issued.",
            styles["BodyText"],
        ))

    else:
        story.extend(_section("Package information", styles))

        story.append(_key_value_table([
            ("Package ID", package_manifest.get("package_id", "Unknown")),
            ("Package schema", package_manifest.get("schema_version", "Unknown")),
            ("Created at", package_manifest.get("created_at", "Unknown")),
            ("Hash algorithm", package_manifest.get("hash_algorithm", "Unknown")),
            ("Signature algorithm", package_manifest.get("signature_algorithm", "Unknown")),
            ("Evidence files", len(package_manifest.get("evidence_files", []))),
        ], styles))

        metadata = package_manifest.get("metadata", {})

        if metadata:
            story.extend(_section("Package metadata", styles))
            story.append(_key_value_table([
                (key, json.dumps(value, ensure_ascii=False))
                for key, value in sorted(metadata.items())
            ], styles))

        story.extend(_section("Package evidence file inventory", styles))

        package_file_rows = [[
            _paragraph("Path", styles["Label"]),
            _paragraph("Size (bytes)", styles["Label"]),
            _paragraph("SHA-256", styles["Label"]),
        ]]

        for entry in package_manifest.get("evidence_files", []):
            package_file_rows.append([
                _paragraph(entry["path"], styles["BodyText"]),
                _paragraph(entry["size_bytes"], styles["BodyText"]),
                _paragraph(entry["sha256"], styles["BodyText"]),
            ])

        package_file_table = Table(
            package_file_rows,
            colWidths=[65 * mm, 30 * mm, 75 * mm],
            repeatRows=1,
        )
        package_file_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(package_file_table)

        if collection is None:
            story.extend(_section("Sanitization assessment", styles))
            story.append(_key_value_table([
                ("Assessment", "NOT_ASSESSED"),
                ("Reason", "No Schema 2.0 collection manifest is present."),
            ], styles))

        else:
            story.extend(_section("Collection information", styles))

            target = collection["target"]
            expected_identity = target["expected_identity"]

            story.append(_key_value_table([
                ("Collection ID", collection["collection"]["collection_id"]),
                ("Collector", collection["collection"]["collector"]),
                ("Adapter", collection["collection"]["adapter"]),
                ("Started (UTC)", collection["collection"]["started_utc"]),
                ("Finished (UTC)", collection["collection"]["finished_utc"]),
                ("Collection status", collection["collection"]["status"]),
                ("Expected device serial", expected_identity["serial"]),
                ("Identity status", collection["identity"]["status"]),
                ("Capture status", collection["capture"]["status"]),
                ("Destructive commands executed",
                 collection["safety"]["destructive_commands_executed"]),
                ("Read-only collection",
                 collection["safety"]["read_only_collection"]),
            ], styles))

            story.extend(_section("Command execution records", styles))

            command_rows = [[
                _paragraph("Command", styles["Label"]),
                _paragraph("Execution", styles["Label"]),
                _paragraph("Exit code", styles["Label"]),
                _paragraph("Duration (s)", styles["Label"]),
            ]]

            for command in collection["commands"]:
                command_rows.append([
                    _paragraph(command["name"], styles["BodyText"]),
                    _paragraph(command["execution_status"], styles["BodyText"]),
                    _paragraph(command["exit_code"], styles["BodyText"]),
                    _paragraph(command["duration_seconds"], styles["BodyText"]),
                ])

            command_table = Table(
                command_rows,
                colWidths=[65 * mm, 38 * mm, 27 * mm, 40 * mm],
                repeatRows=1,
            )
            command_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(command_table)

            story.extend(_section("Evidence artifact inventory", styles))

            artifact_rows = [[
                _paragraph("Artifact", styles["Label"]),
                _paragraph("Role", styles["Label"]),
                _paragraph("Path", styles["Label"]),
                _paragraph("Size (bytes)", styles["Label"]),
                _paragraph("SHA-256", styles["Label"]),
            ]]

            for artifact in collection["artifacts"]:
                artifact_rows.append([
                    _paragraph(artifact["artifact_id"], styles["BodyText"]),
                    _paragraph(artifact["role"], styles["BodyText"]),
                    _paragraph(artifact["path"], styles["BodyText"]),
                    _paragraph(artifact["size_bytes"], styles["BodyText"]),
                    _paragraph(artifact["hash"]["value"], styles["BodyText"]),
                ])

            artifact_table = Table(
                artifact_rows,
                colWidths=[27 * mm, 22 * mm, 39 * mm, 23 * mm, 59 * mm],
                repeatRows=1,
            )
            artifact_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(artifact_table)

            story.extend(_section("Sanitization assessment", styles))

            story.append(_key_value_table([
                ("Assessment result", assessment["status"]),
                ("Assessment engine", assessment["engine_version"]),
            ], styles))

            story.extend(_section("Separately supplied operation evidence", styles))
            operation_evidence = assessment.get("operation")

            if operation_evidence is None:
                operation_rows = [
                    ("Operation evidence", "NOT SUPPLIED"),
                ]
            else:
                operation_rows = [
                    ("Operation status", operation_evidence["status"]),
                    ("Sanitization technique", operation_evidence["technique"] or "Not recorded"),
                    ("Verification status", operation_evidence["verification"]),
                    ("Validation status", operation_evidence["validation"]),
                ]

            story.append(_key_value_table(operation_rows, styles))

            for finding in assessment["findings"]:
                story.append(Spacer(1, 2 * mm))
                story.append(Paragraph(
                    f"<b>{escape(finding['severity'])}: "
                    f"{escape(finding['code'])}</b>",
                    styles["BodyText"],
                ))
                story.append(Paragraph(
                    escape(finding["message"]),
                    styles["BodyText"],
                ))

            story.extend(_section("Audit limitations", styles))
            story.append(Paragraph(
                "A valid package signature and matching artifact hashes "
                "establish package integrity relative to the signing key. "
                "They do not prove that a storage device was successfully "
                "sanitized. An assessment of UNDER_REVIEW is not a "
                "conformance certificate. Technique-specific verification, "
                "validation and independent audit review remain necessary.",
                styles["BodyText"],
            ))

    # Build to a temporary file, then publish the completed PDF.
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=".ose-report-",
        suffix=".pdf",
        dir=output.parent,
    )
    os.close(file_descriptor)

    try:
        document = SimpleDocTemplate(
            temporary_name,
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=18 * mm,
            bottomMargin=20 * mm,
            title="OpenSanitize Evidence Audit Report",
            author="OpenSanitize Evidence",
        )

        document.build(
            story,
            onFirstPage=_page_footer,
            onLaterPages=_page_footer,
        )

        if output.exists():
            raise FileExistsError(
                f"Report output appeared during generation: {output}"
            )

        # Hard-link publication is atomic and fails if the destination exists.
        os.link(temporary_name, output)
        os.unlink(temporary_name)

    except Exception:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
        raise

    return {
        "output_path": str(output),
        "integrity_valid": integrity["valid"],
        "assessment_status": (
            assessment["status"] if assessment is not None else "NOT_ASSESSED"
        ),
        "collection_id": (
            collection["collection"]["collection_id"]
            if collection is not None
            else None
        ),
    }
