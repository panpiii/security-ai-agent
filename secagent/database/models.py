"""
Database models for storing scan history and results.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import Column, Integer, String, DateTime, Float, Text, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from pydantic import BaseModel

Base = declarative_base()


class ScanRecord(Base):
    """Database model for storing scan records."""
    __tablename__ = "scan_records"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True, nullable=False)
    target_path = Column(String, nullable=False)
    scan_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Risk scores
    overall_risk_score = Column(Float, nullable=False)
    dependency_risk_score = Column(Float, nullable=False)
    code_risk_score = Column(Float, nullable=False)
    
    # Summary counts
    dependency_vulnerabilities = Column(Integer, default=0)
    code_issues = Column(Integer, default=0)
    
    # Raw results (JSON)
    scan_results = Column(JSON, nullable=False)
    risk_factors = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    
    # Metadata
    scanner_versions = Column(JSON, nullable=True)
    scan_duration_seconds = Column(Float, nullable=True)
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)
    
    # Optional fields
    project_name = Column(String, nullable=True)
    branch_name = Column(String, nullable=True)
    commit_hash = Column(String, nullable=True)


class ScanSummary(BaseModel):
    """Pydantic model for scan summary data."""
    scan_id: str
    target_path: str
    scan_timestamp: datetime
    overall_risk_score: float
    dependency_risk_score: float
    code_risk_score: float
    dependency_vulnerabilities: int
    code_issues: int
    project_name: Optional[str] = None
    branch_name: Optional[str] = None
    commit_hash: Optional[str] = None
    success: bool = True


class ScanDetails(BaseModel):
    """Pydantic model for detailed scan data."""
    scan_id: str
    target_path: str
    scan_timestamp: datetime
    overall_risk_score: float
    dependency_risk_score: float
    code_risk_score: float
    dependency_vulnerabilities: int
    code_issues: int
    scan_results: Dict[str, Any]
    risk_factors: Optional[Dict[str, Any]] = None
    recommendations: Optional[List[str]] = None
    project_name: Optional[str] = None
    branch_name: Optional[str] = None
    commit_hash: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None


class RiskTrend(BaseModel):
    """Pydantic model for risk trend analysis."""
    date: str
    overall_risk_score: float
    dependency_risk_score: float
    code_risk_score: float
    dependency_vulnerabilities: int
    code_issues: int


class DashboardStats(BaseModel):
    """Pydantic model for dashboard statistics."""
    total_scans: int
    recent_scans: int  # Last 7 days
    average_risk_score: float
    high_risk_scans: int  # Risk score > 7
    critical_vulnerabilities: int
    high_severity_code_issues: int
    last_scan_date: Optional[datetime] = None
