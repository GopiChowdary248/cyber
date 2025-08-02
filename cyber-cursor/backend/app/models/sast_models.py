from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class Project(Base):
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    repo_url = Column(Text)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = relationship("SASTScan", back_populates="project", cascade="all, delete-orphan")

class SASTScan(Base):
    __tablename__ = "sast_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"))
    triggered_by = Column(String(255), nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    status = Column(String(20), default="running")  # running, completed, failed
    scan_type = Column(String(50), default="full")  # full, incremental, quick
    total_files = Column(Integer, default=0)
    scanned_files = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    project = relationship("Project", back_populates="scans")
    results = relationship("SASTResult", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("SASTReport", back_populates="scan", cascade="all, delete-orphan")

class SASTResult(Base):
    __tablename__ = "sast_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("sast_scans.id", ondelete="CASCADE"))
    file_path = Column(Text, nullable=False)
    line_no = Column(Integer)
    column_no = Column(Integer)
    vulnerability = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    recommendation = Column(Text)
    tool_name = Column(String(50), nullable=False)  # bandit, eslint, semgrep, pylint
    cwe_id = Column(String(20))
    confidence = Column(String(20), default="medium")  # high, medium, low
    detected_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="open")  # open, fixed, false_positive, wont_fix
    
    # Relationships
    scan = relationship("SASTScan", back_populates="results")

class SASTReport(Base):
    __tablename__ = "sast_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("sast_scans.id", ondelete="CASCADE"))
    report_type = Column(String(20), nullable=False)  # summary, detailed, pdf, csv
    report_data = Column(JSON)
    generated_at = Column(DateTime, default=datetime.utcnow)
    file_path = Column(Text)
    
    # Relationships
    scan = relationship("SASTScan", back_populates="reports") 