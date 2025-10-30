# models.py
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Float, Text, ForeignKey, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

import os

DB_URL = os.environ.get("VULN_DB_URL", "sqlite:///vuln_scanner.db")

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source = Column(String(128), default="scheduler")  # e.g. manual/scheduler
    total_cves = Column(Integer, default=0)
    high_severity_count = Column(Integer, default=0)


class CVE(Base):
    __tablename__ = "cves"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(64), unique=True, index=True, nullable=False)
    summary = Column(Text, nullable=True)
    cvss = Column(Float, nullable=True)
    severity = Column(String(32), nullable=True)
    affected_products = Column(Text, nullable=True)  # comma-separated or JSON as string
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    histories = relationship("CVEHistory", back_populates="cve")


class CVEHistory(Base):
    __tablename__ = "cve_histories"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(64), index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    summary = Column(Text, nullable=True)
    cvss = Column(Float, nullable=True)
    severity = Column(String(32), nullable=True)
    affected_products = Column(Text, nullable=True)

    scan = relationship("Scan")
    cve = relationship("CVE", primaryjoin="CVEHistory.cve_id==CVE.cve_id", back_populates="histories")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, index=True)
    severity = Column(String)
    reason = Column(String)
    meta_data = Column(JSON)  # ✅ renamed from metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    dispatched = Column(Integer, default=0)


def init_db():
    Base.metadata.create_all(bind=engine)
