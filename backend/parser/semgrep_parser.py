"""
Parses a Semgrep JSON report and inserts the findings into
the Scans and Vulnerabilities tables.
"""
import json
import sys
import os

# Let this script import from backend/ (database.py, models.py)
# even though it lives in backend/parser/
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from database import SessionLocal
from models import Scan, Vulnerability


# Semgrep's own severity words don't match our "critical/high/medium/low"
# scale, so we translate them here.
SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def parse_semgrep_report(report_path: str, project_id: int = 1):
    with open(report_path, "r") as f:
        data = json.load(f)

    results = data.get("results", [])

    db = SessionLocal()
    try:
        # Create one Scan row to represent this whole run
        scan = Scan(
            project_id=project_id,
            scanner_type="semgrep",
            status="completed",
            raw_report_path=report_path,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)  # gets scan.id populated after insert

        # Insert one Vulnerability row per finding
        for result in results:
            extra = result.get("extra", {})
            severity_raw = extra.get("severity", "INFO")

            vuln = Vulnerability(
                scan_id=scan.id,
                title=result.get("check_id", "unknown_check"),
                description=extra.get("message", ""),
                severity=SEVERITY_MAP.get(severity_raw, "low"),
                file_path=result.get("path"),
                line_number=result.get("start", {}).get("line"),
            )
            db.add(vuln)

        db.commit()
        print(f"Inserted 1 scan and {len(results)} vulnerabilities (scan_id={scan.id})")

    finally:
        db.close()


if __name__ == "__main__":
    report_path = sys.argv[1] if len(sys.argv) > 1 else "../../security/semgrep/report.json"
    parse_semgrep_report(report_path)
