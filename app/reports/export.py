"""Secure export utilities with spreadsheet formula injection protection."""

import csv
import io
import json
from typing import Any, List

from app.database.models import Finding

# Dangerous prefix characters that spreadsheet software (Excel, Calc, Sheets) interpret as formulas
DANGEROUS_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n", "%")


def sanitize_csv_cell(value: Any) -> str:
    """Sanitize cell value against CSV / Spreadsheet Formula Injection (CWE-1236).

    If the first non-whitespace character is a formula prefix, prefix the original cell
    with a single quote so leading spaces cannot bypass spreadsheet formula protection.
    """
    if value is None:
        return ""

    text = str(value)
    if not text:
        return ""

    if text.lstrip(" ").startswith(DANGEROUS_FORMULA_PREFIXES):
        return f"'{text}"

    return text


def export_findings_to_csv(findings: List[Finding]) -> str:
    """Serialize finding records into sanitized CSV string."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header
    headers = [
        "Finding ID",
        "Category",
        "Severity",
        "Title",
        "Description",
        "Target Component",
        "Affected Test Case",
        "Detection Method",
        "Remediation",
        "Creation Timestamp",
        "Retest Status",
    ]
    writer.writerow(headers)

    # Data rows
    for f in findings:
        row = [
            sanitize_csv_cell(f.id),
            sanitize_csv_cell(f.category),
            sanitize_csv_cell(f.severity),
            sanitize_csv_cell(f.title),
            sanitize_csv_cell(f.description),
            sanitize_csv_cell(f.target_component),
            sanitize_csv_cell(f.affected_test_case),
            sanitize_csv_cell(f.detection_method),
            sanitize_csv_cell(f.remediation),
            sanitize_csv_cell(f.creation_timestamp.isoformat() if f.creation_timestamp else ""),
            sanitize_csv_cell(f.retest_status),
        ]
        writer.writerow(row)

    return output.getvalue()


def export_report_to_json(report_dict: dict) -> str:
    """Serialize report dictionary to formatted JSON."""
    return json.dumps(report_dict, indent=2, default=str)
