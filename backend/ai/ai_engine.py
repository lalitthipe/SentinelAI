"""
Calls the Groq API (free tier) to generate a summary, risk score, and
remediation suggestion for a given vulnerability, then stores it in
the AI_Reports table.
"""
import os
import sys
import json
from dotenv import load_dotenv
from groq import Groq

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from database import SessionLocal
from models import Vulnerability, AIReport

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))


def generate_ai_report(vulnerability_id: int):
    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        if not vuln:
            print(f"No vulnerability found with id={vulnerability_id}")
            return

        existing = db.query(AIReport).filter(AIReport.vulnerability_id == vulnerability_id).first()
        if existing:
            print(f"AI report already exists for vulnerability {vulnerability_id}, skipping.")
            return

        prompt = f"""You are a security analyst assistant. Given this vulnerability finding, respond ONLY in valid JSON with exactly these three fields: "summary" (a plain-English explanation, 2-3 sentences), "risk_score" (an integer from 1-10), and "remediation" (a specific, actionable fix, 2-3 sentences). Do not include any text outside the JSON object.

Vulnerability:
Title: {vuln.title}
Description: {vuln.description}
Severity: {vuln.severity}
File: {vuln.file_path}
Line: {vuln.line_number}
"""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )

        result = json.loads(response.choices[0].message.content)

        ai_report = AIReport(
            vulnerability_id=vuln.id,
            summary=result.get("summary", ""),
            risk_score=result.get("risk_score", 0),
            remediation=result.get("remediation", ""),
        )
        db.add(ai_report)
        db.commit()
        print(f"AI report created for vulnerability {vulnerability_id}: risk_score={ai_report.risk_score}")

    finally:
        db.close()


def generate_reports_for_all_open_vulnerabilities():
    db = SessionLocal()
    try:
        open_vulns = db.query(Vulnerability).filter(Vulnerability.status == "open").all()
        ids = [v.id for v in open_vulns]
    finally:
        db.close()

    for vid in ids:
        generate_ai_report(vid)


if __name__ == "__main__":
    generate_reports_for_all_open_vulnerabilities()
