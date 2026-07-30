from groq import Groq
from fastapi.responses import StreamingResponse
import csv
import io
from fastapi.security import OAuth2PasswordRequestForm
from auth.auth import hash_password, verify_password, create_access_token, get_current_user
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, get_db
import models
import os
from dotenv import load_dotenv
load_dotenv()
from pydantic import BaseModel

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SentinelAI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://192.168.56.101:5173",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def log_action(db: Session, user_id: int, action: str, details: str = None):
    entry = models.AuditLog(user_id=user_id, action=action, details=details)
    db.add(entry)
    db.commit()

def require_admin(current_user: models.User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/vulnerabilities")
def get_vulnerabilities(
    severity: str = None,
    search: str = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    query = db.query(models.Vulnerability)

    if severity:
        query = query.filter(models.Vulnerability.severity == severity)

    if search:
        query = query.filter(models.Vulnerability.title.ilike(f"%{search}%"))

    vulns = query.all()
    return [
        {
            "id": v.id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity,
            "file_path": v.file_path,
            "line_number": v.line_number,
            "status": v.status,
        }
        for v in vulns
    ]


@app.get("/scans")
def get_scans(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    scans = db.query(models.Scan).all()
    return [
        {
            "id": s.id,
            "scanner_type": s.scanner_type,
            "status": s.status,
            "started_at": str(s.started_at),
        }
        for s in scans
    ]

@app.get("/vulnerabilities/{vuln_id}/ai-report")
def get_ai_report(vuln_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    report = db.query(models.AIReport).filter(models.AIReport.vulnerability_id == vuln_id).first()
    if not report:
        return {"detail": "No AI report found for this vulnerability"}
    return {
        "summary": report.summary,
        "risk_score": report.risk_score,
        "remediation": report.remediation,
    }

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

@app.post("/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    username = payload.username
    email = payload.email
    password = payload.password
    existing = db.query(models.User).filter(models.User.username == username).first()
    if existing:
        return {"detail": "Username already exists"}

    new_user = models.User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role="viewer",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    log_action(db, new_user.id, "register", f"New user {new_user.username} registered")
    return {"id": new_user.id, "username": new_user.username, "role": new_user.role}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        return {"detail": "Incorrect username or password"}

    access_token = create_access_token(data={"sub": user.username})
    log_action(db, user.id, "login", f"User {user.username} logged in")
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me")
def read_current_user(current_user: models.User = Depends(get_current_user)):
    # This endpoint only works if a valid JWT token is provided —
    # it's our proof that auth is actually protecting something.
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
    }

@app.get("/audit-logs")
def get_audit_logs(db: Session = Depends(get_db), current_user: models.User = Depends(require_admin)):
    logs = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).all()
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "details": log.details,
            "timestamp": str(log.timestamp),
        }
        for log in logs
    ]

class NetworkHostRequest(BaseModel):
    ip_address: str
    hostname: str = None
    open_ports: str = None

@app.post("/network/hosts")
def add_network_host(
    payload: NetworkHostRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    ip_address = payload.ip_address
    hostname = payload.hostname
    open_ports = payload.open_ports
    # If this IP already exists, update it instead of creating a duplicate
    # If this IP already exists, update it instead of creating a duplicate
    existing = db.query(models.NetworkDevice).filter(models.NetworkDevice.ip_address == ip_address).first()
    if existing:
        existing.hostname = hostname
        existing.open_ports = open_ports
        db.commit()
        db.refresh(existing)
        return {"id": existing.id, "ip_address": existing.ip_address, "status": "updated"}

    device = models.NetworkDevice(ip_address=ip_address, hostname=hostname, open_ports=open_ports)
    db.add(device)
    db.commit()
    db.refresh(device)
    return {"id": device.id, "ip_address": device.ip_address, "status": "created"}


@app.get("/network/hosts")
def get_network_hosts(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    devices = db.query(models.NetworkDevice).all()
    return [
        {
            "id": d.id,
            "ip_address": d.ip_address,
            "hostname": d.hostname,
            "open_ports": d.open_ports,
            "last_seen": str(d.last_seen),
        }
        for d in devices
    ]


class SnortAlertRequest(BaseModel):
    source_ip: str
    dest_ip: str
    alert_message: str
    severity: str = "medium"
    raw_log: str = None

@app.post("/network/alerts")
def add_snort_alert(
    payload: SnortAlertRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    source_ip = payload.source_ip
    dest_ip = payload.dest_ip
    alert_message = payload.alert_message
    severity = payload.severity
    raw_log = payload.raw_log
    alert = models.SnortAlert(
        source_ip=source_ip,
        dest_ip=dest_ip,
        alert_message=alert_message,
        severity=severity,
        raw_log=raw_log,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return {"id": alert.id, "status": "created"}


@app.get("/network/alerts")
def get_snort_alerts(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    alerts = db.query(models.SnortAlert).order_by(models.SnortAlert.created_at.desc()).all()
    return [
        {
            "id": a.id,
            "source_ip": a.source_ip,
            "dest_ip": a.dest_ip,
            "alert_message": a.alert_message,
            "severity": a.severity,
            "created_at": str(a.created_at),
        }
        for a in alerts
    ]

@app.get("/reports/vulnerabilities/csv")
def export_vulnerabilities_csv(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    vulns = db.query(models.Vulnerability).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Title", "Description", "Severity", "File Path", "Line Number", "Status"])

    for v in vulns:
        writer.writerow([v.id, v.title, v.description, v.severity, v.file_path, v.line_number, v.status])

    output.seek(0)
    log_action(db, current_user.id, "report_exported", "Exported vulnerabilities CSV")

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities_report.csv"},
    )
@app.get("/reports/vulnerabilities/pdf")
def export_vulnerabilities_pdf(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet

    vulns = db.query(models.Vulnerability).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [Paragraph("SentinelAI Vulnerability Report", styles["Title"])]

    data = [["Severity", "Title", "File", "Line", "Status"]]
    for v in vulns:
        data.append([v.severity, v.title[:50], v.file_path, str(v.line_number), v.status])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3b82f6")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f0f0")]),
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)

    log_action(db, current_user.id, "report_exported", "Exported vulnerabilities PDF")

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities_report.pdf"},
    )

@app.post("/ai-assistant/ask")
def ask_ai_assistant(
    question: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    prompt = f"""You are a helpful security analyst assistant embedded in a DevSecOps dashboard called SentinelAI. Answer the user's question clearly and concisely, in a way useful to a security engineer or developer. Keep answers focused and practical, 3-5 sentences unless the question needs more detail.

Question: {question}
"""

    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
    )

    answer = response.choices[0].message.content
    log_action(db, current_user.id, "ai_assistant_query", f"Asked: {question[:100]}")

    return {"question": question, "answer": answer}

@app.get("/dashboard/summary")
def get_dashboard_summary(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    total_vulns = db.query(models.Vulnerability).count()

    severity_counts = {}
    for sev in ["critical", "high", "medium", "low"]:
        severity_counts[sev] = db.query(models.Vulnerability).filter(models.Vulnerability.severity == sev).count()

    recent_scans = (
        db.query(models.Scan)
        .order_by(models.Scan.started_at.desc())
        .limit(5)
        .all()
    )

    total_hosts = db.query(models.NetworkDevice).count()
    recent_alerts = db.query(models.SnortAlert).count()

    score = 100 - (severity_counts["critical"] * 10 + severity_counts["high"] * 5 + severity_counts["medium"] * 2 + severity_counts["low"] * 1)
    score = max(score, 0)

    return {
        "security_score": score,
        "total_vulnerabilities": total_vulns,
        "severity_counts": severity_counts,
        "recent_scans": [
            {
                "id": s.id,
                "scanner_type": s.scanner_type,
                "status": s.status,
                "started_at": str(s.started_at),
            }
            for s in recent_scans
        ],
        "total_hosts": total_hosts,
        "total_alerts": recent_alerts,
    }
