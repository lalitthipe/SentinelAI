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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/vulnerabilities")
def get_vulnerabilities(db: Session = Depends(get_db)):
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
def get_scans(db: Session = Depends(get_db)):
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
