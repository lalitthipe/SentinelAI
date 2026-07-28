"""
Parses a Trivy JSON report (filesystem scan) and inserts findings
into the Scans and Vulnerabilities tables.
"""
import json
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from database import SessionLocal
from models import Scan, Vulnerability


# Trivy's own severity words map directly to ours, just lowercase them
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
        scan = Scan(
            project_id=project_id,
            scanner_type="trivy",
            status="completed",
            raw_report_path=report_path,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        total_vulns = 0
        # Trivy groups findings by target (e.g. package-lock.json),
        # so we loop through each target, then each vulnerability inside it.
        for result in results:
            target = result.get("Target", "unknown")
            vulnerabilities = result.get("Vulnerabilities", []) or []

            for v in vulnerabilities:
                vuln = Vulnerability(
                    scan_id=scan.id,
                    title=v.get("VulnerabilityID", "unknown_cve"),
                    description=v.get("Title") or v.get("Description", ""),
                    severity=SEVERITY_MAP.get(v.get("Severity", "UNKNOWN"), "low"),
                    cve_id=v.get("VulnerabilityID"),
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
