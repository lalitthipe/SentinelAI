from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="viewer")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    repo_url = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scans = relationship("Scan", back_populates="project")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    scanner_type = Column(String, nullable=False)
    status = Column(String, default="pending")
    raw_report_path = Column(String)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    title = Column(String, nullable=False)
    description = Column(String)
    severity = Column(String)
    cve_id = Column(String, nullable=True)
    file_path = Column(String, nullable=True)
    line_number = Column(Integer, nullable=True)
    status = Column(String, default="open")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="vulnerabilities")
    ai_report = relationship("AIReport", back_populates="vulnerability", uselist=False)


class AIReport(Base):
    __tablename__ = "ai_reports"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), unique=True)
    summary = Column(String)
    risk_score = Column(Integer)
    remediation = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    vulnerability = relationship("Vulnerability", back_populates="ai_report")


class NetworkDevice(Base):
    __tablename__ = "network_devices"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    open_ports = Column(String)
    last_seen = Column(DateTime(timezone=True), server_default=func.now())


class SnortAlert(Base):
    __tablename__ = "snort_alerts"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String)
    dest_ip = Column(String)
    alert_message = Column(String)
    severity = Column(String)
    raw_log = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String, nullable=False)
    details = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
