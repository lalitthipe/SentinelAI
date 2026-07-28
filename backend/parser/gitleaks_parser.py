"""
Parses a Gitleaks JSON report and inserts findings into
the Scans and Vulnerabilities tables.
"""
import json
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from database import SessionLocal
from models import Scan, Vulnerability


def parse_gitleaks_report(report_path: str, project_id: int = 1):
    with open(report_path, "r") as f:
        data = json.load(f)

    # Gitleaks outputs a flat JSON array, unlike Semgrep/Trivy's nested structure
    findings = data if isinstance(data, list) else []

    db = SessionLocal()
    try:
        scan = Scan(
            project_id=project_id,
            scanner_type="gitleaks",
            status="completed",
            raw_report_path=report_path,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        for finding in findings:
            vuln = Vulnerability(
                scan_id=scan.id,
                title=f"Secret detected: {finding.get('RuleID', 'unknown')}",
                description=finding.get("Description", ""),
                severity="critical",  # leaked secrets are always treated as critical
                file_path=finding.get("File"),
                line_number=finding.get("StartLine"),
            )
            db.add(vuln)

        db.commit()
        print(f"Inserted 1 scan and {len(findings)} vulnerabilities (scan_id={scan.id})")

    finally:
        db.close()


if __name__ == "__main__":
    report_path = sys.argv[1] if len(sys.argv) > 1 else "../../security/gitleaks/report.json"
    parse_gitleaks_report(report_path)
