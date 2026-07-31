"""
Parses a Semgrep JSON report and inserts the findings into
the Scans and Vulnerabilities tables.
"""
import json
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from database import SessionLocal
from models import Scan, Vulnerability, AIReport

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
        old_scan_ids = [
            s.id for s in db.query(Scan)
            .filter(Scan.project_id == project_id, Scan.scanner_type == "semgrep")
            .all()
        ]
        if old_scan_ids:
            old_vuln_ids = [
                v.id for v in db.query(Vulnerability)
                .filter(Vulnerability.scan_id.in_(old_scan_ids))
                .all()
            ]
            if old_vuln_ids:
                db.query(AIReport).filter(
                    AIReport.vulnerability_id.in_(old_vuln_ids)
                ).delete(synchronize_session=False)
            db.query(Vulnerability).filter(
                Vulnerability.scan_id.in_(old_scan_ids)
            ).delete(synchronize_session=False)
            db.query(Scan).filter(Scan.id.in_(old_scan_ids)).delete(synchronize_session=False)
            db.commit()

        scan = Scan(
            project_id=project_id,
            scanner_type="semgrep",
            status="completed",
            raw_report_path=report_path,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        seen = set()
        inserted = 0
        for result in results:
            extra = result.get("extra", {})
            severity_raw = extra.get("severity", "INFO")
            file_path = result.get("path")
            line_number = result.get("start", {}).get("line")
            title = result.get("check_id", "unknown_check")

            key = (title, file_path, line_number)
            if key in seen:
                continue
            seen.add(key)

            vuln = Vulnerability(
                scan_id=scan.id,
                title=title,
                description=extra.get("message", ""),
                severity=SEVERITY_MAP.get(severity_raw, "low"),
                file_path=file_path,
                line_number=line_number,
            )
            db.add(vuln)
            inserted += 1

        db.commit()
        print(f"Inserted 1 scan and {inserted} vulnerabilities (scan_id={scan.id})")
    finally:
        db.close()

if __name__ == "__main__":
    report_path = sys.argv[1] if len(sys.argv) > 1 else "../../security/semgrep/report.json"
    parse_semgrep_report(report_path)
