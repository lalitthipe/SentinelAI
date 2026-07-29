from fastapi.security import OAuth2PasswordRequestForm
from auth.auth import hash_password, verify_password, create_access_token, get_current_user
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, get_db
import models

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SentinelAI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def log_action(db: Session, user_id: int, action: str, details: str = None):
    entry = models.AuditLog(user_id=user_id, action=action, details=details)
    db.add(entry)
    db.commit()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/vulnerabilities")
def get_vulnerabilities(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # Fetch all vulnerability rows from Postgres and return as JSON
    vulns = db.query(models.Vulnerability).all()
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
def get_ai_report(vuln_id: int, db: Session = Depends(get_db)):
    report = db.query(models.AIReport).filter(models.AIReport.vulnerability_id == vuln_id).first()
    if not report:
        return {"detail": "No AI report found for this vulnerability"}
    return {
        "summary": report.summary,
        "risk_score": report.risk_score,
        "remediation": report.remediation,
    }

@app.post("/register")
def register(username: str, email: str, password: str, db: Session = Depends(get_db)):
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
def get_audit_logs(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
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
