"""
Database Models and Configuration
SQLite-based persistence for users, audit logs, test results, and alerts
"""

import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging

logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///vpn_toolkit.db')
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class User(Base):
    """User account model"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="viewer")  # admin, tester, viewer
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)


class AuditLog(Base):
    """Audit log for all actions"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    action = Column(String)  # login, run_test, create_report, etc
    resource = Column(String)  # what was accessed
    status = Column(String)  # success, failure, pending
    details = Column(JSON)  # additional context
    ip_address = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class TestResult(Base):
    """Pentesting test results"""
    __tablename__ = "test_results"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    test_type = Column(String)  # sql_injection, xss, port_scan, cert_analysis, etc
    target = Column(String)  # URL or host tested
    status = Column(String)  # completed, in_progress, failed
    result = Column(JSON)  # test result data
    vulnerabilities_found = Column(Integer, default=0)
    severity = Column(String)  # CRITICAL, HIGH, MEDIUM, LOW
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime)
    duration_seconds = Column(Float)
    notes = Column(Text)


class Report(Base):
    """Generated security reports"""
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    title = Column(String)
    description = Column(Text)
    report_type = Column(String)  # summary, detailed, executive
    test_results = Column(JSON)  # list of test result IDs included
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    pdf_path = Column(String)
    html_path = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    generated_at = Column(DateTime)


class ThreatAlert(Base):
    """Threat detection alerts"""
    __tablename__ = "threat_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String)  # port_scan, brute_force, ddos, etc
    severity = Column(String)  # CRITICAL, HIGH, MEDIUM, LOW
    source_ip = Column(String)
    destination_ip = Column(String)
    details = Column(JSON)
    blocked = Column(Boolean, default=False)
    notified = Column(Boolean, default=False)
    notification_method = Column(String)  # email, slack, log
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class VPNSession(Base):
    """VPN session tracking"""
    __tablename__ = "vpn_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    connections_count = Column(Integer, default=0)
    status = Column(String)  # active, stopped, interrupted
    notes = Column(Text)


# Create all tables
def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully")


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("✓ Database initialized")
