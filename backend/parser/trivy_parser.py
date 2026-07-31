"""
Parses a Trivy JSON report (filesystem scan) and inserts findings
into the Scans and Vulnerabilities tables.
"""
import json
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from database import SessionLocal
from models import Scan, Vulnerability, AIReport

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}

def parse_trivy_report(report_path: str, project_id: int = 1):
    with open(report_path, "r") as f:
        data = json.load(f)

    results = data.get("Results", []) or []
    db = SessionLocal()
    try:
        old_scan_ids = [
            s.id for s in db.query(Scan)
            .filter(Scan.project_id == project_id, Scan.scanner_type == "trivy")
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
            scanner_type="trivy",
            status="completed",
            raw_report_path=report_path,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        seen = set()
        total_vulns = 0
        for result in results:
            target = result.get("Target", "unknown")
            vulnerabilities = result.get("Vulnerabilities", []) or []
            for v in vulnerabilities:
                cve_id = v.get("VulnerabilityID", "unknown_cve")

                key = (cve_id, target)
                if key in seen:
                    continue
                seen.add(key)

                vuln = Vulnerability(
                    scan_id=scan.id,
                    title=cve_id,
                    description=v.get("Title") or v.get("Description", ""),
                    severity=SEVERITY_MAP.get(v.get("Severity", "UNKNOWN"), "low"),
                    cve_id=cve_id,
                    file_path=target,
                )
                db.add(vuln)
                total_vulns += 1

        db.commit()
        print(f"Inserted 1 scan and {total_vulns} vulnerabilities (scan_id={scan.id})")
    finally:
        db.close()

if __name__ == "__main__":
    report_path = sys.argv[1] if len(sys.argv) > 1 else "../../security/trivy/report.json"
    parse_trivy_report(report_path)
