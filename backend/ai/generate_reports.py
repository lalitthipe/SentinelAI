"""
Generates AI reports for any vulnerability that doesn't already have one.
Uses the same Groq client pattern as the AI Assistant endpoint.
"""
import os
import sys
from groq import Groq
from dotenv import load_dotenv

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from database import SessionLocal
from models import Vulnerability, AIReport

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def generate_report(vuln: Vulnerability):
    prompt = f"""You are a security analyst. Analyze this vulnerability finding and respond in EXACTLY this format, nothing else:

RISK_SCORE: <a number 1-10>
SUMMARY: <2-3 sentence plain-English explanation of the issue>
REMEDIATION: <2-3 sentence actionable fix>

Finding:
Title: {vuln.title}
Severity: {vuln.severity}
File: {vuln.file_path}
Line: {vuln.line_number}
Description: {vuln.description or "N/A"}
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.choices[0].message.content

    risk_score = 5
    summary = ""
    remediation = ""
    for line in text.splitlines():
        if line.startswith("RISK_SCORE:"):
            try:
                risk_score = int(line.replace("RISK_SCORE:", "").strip())
            except ValueError:
                pass
        elif line.startswith("SUMMARY:"):
            summary = line.replace("SUMMARY:", "").strip()
        elif line.startswith("REMEDIATION:"):
            remediation = line.replace("REMEDIATION:", "").strip()

    return risk_score, summary, remediation

def main():
    db = SessionLocal()
    try:
        existing_ids = {r.vulnerability_id for r in db.query(AIReport).all()}
        vulns = db.query(Vulnerability).filter(~Vulnerability.id.in_(existing_ids)).all() if existing_ids else db.query(Vulnerability).all()

        print(f"Generating reports for {len(vulns)} vulnerabilities...")
        for v in vulns:
            risk_score, summary, remediation = generate_report(v)
            report = AIReport(
                vulnerability_id=v.id,
                risk_score=risk_score,
                summary=summary,
                remediation=remediation,
            )
            db.add(report)
            db.commit()
            print(f"  #{v.id} {v.title} -> risk {risk_score}")
    finally:
        db.close()

if __name__ == "__main__":
    main()
