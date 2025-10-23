"""
Repository for scan data operations.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from .models import ScanRecord, ScanSummary, ScanDetails, RiskTrend, DashboardStats
from .database import db_manager


class ScanRepository:
    """Repository for scan data operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_scan_record(self, 
                         target_path: str,
                         scan_results: Dict[str, Any],
                         risk_score: float,
                         dependency_risk: float,
                         code_risk: float,
                         dependency_vulns: int,
                         code_issues: int,
                         risk_factors: Optional[Dict[str, Any]] = None,
                         recommendations: Optional[List[str]] = None,
                         project_name: Optional[str] = None,
                         branch_name: Optional[str] = None,
                         commit_hash: Optional[str] = None,
                         scan_duration: Optional[float] = None,
                         success: bool = True,
                         error_message: Optional[str] = None) -> str:
        """Create a new scan record."""
        scan_id = str(uuid.uuid4())
        
        scan_record = ScanRecord(
            scan_id=scan_id,
            target_path=target_path,
            overall_risk_score=risk_score,
            dependency_risk_score=dependency_risk,
            code_risk_score=code_risk,
            dependency_vulnerabilities=dependency_vulns,
            code_issues=code_issues,
            scan_results=scan_results,
            risk_factors=risk_factors,
            recommendations=recommendations,
            project_name=project_name,
            branch_name=branch_name,
            commit_hash=commit_hash,
            scan_duration_seconds=scan_duration,
            success=success,
            error_message=error_message
        )
        
        self.db.add(scan_record)
        self.db.commit()
        self.db.refresh(scan_record)
        
        return scan_id
    
    def get_scan_by_id(self, scan_id: str) -> Optional[ScanDetails]:
        """Get scan details by ID."""
        scan = self.db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        if not scan:
            return None
        
        return ScanDetails(
            scan_id=scan.scan_id,
            target_path=scan.target_path,
            scan_timestamp=scan.scan_timestamp,
            overall_risk_score=scan.overall_risk_score,
            dependency_risk_score=scan.dependency_risk_score,
            code_risk_score=scan.code_risk_score,
            dependency_vulnerabilities=scan.dependency_vulnerabilities,
            code_issues=scan.code_issues,
            scan_results=scan.scan_results,
            risk_factors=scan.risk_factors,
            recommendations=scan.recommendations,
            project_name=scan.project_name,
            branch_name=scan.branch_name,
            commit_hash=scan.commit_hash,
            success=scan.success,
            error_message=scan.error_message
        )
    
    def get_recent_scans(self, limit: int = 50) -> List[ScanSummary]:
        """Get recent scan summaries."""
        scans = (self.db.query(ScanRecord)
                .order_by(desc(ScanRecord.scan_timestamp))
                .limit(limit)
                .all())
        
        return [
            ScanSummary(
                scan_id=scan.scan_id,
                target_path=scan.target_path,
                scan_timestamp=scan.scan_timestamp,
                overall_risk_score=scan.overall_risk_score,
                dependency_risk_score=scan.dependency_risk_score,
                code_risk_score=scan.code_risk_score,
                dependency_vulnerabilities=scan.dependency_vulnerabilities,
                code_issues=scan.code_issues,
                project_name=scan.project_name,
                branch_name=scan.branch_name,
                commit_hash=scan.commit_hash,
                success=scan.success
            )
            for scan in scans
        ]
    
    def get_risk_trends(self, days: int = 30) -> List[RiskTrend]:
        """Get risk trends over time."""
        since_date = datetime.utcnow() - timedelta(days=days)
        
        scans = (self.db.query(ScanRecord)
                .filter(ScanRecord.scan_timestamp >= since_date)
                .filter(ScanRecord.success == True)
                .order_by(ScanRecord.scan_timestamp)
                .all())
        
        # Group by date and calculate averages
        daily_data = {}
        for scan in scans:
            date_key = scan.scan_timestamp.date().isoformat()
            if date_key not in daily_data:
                daily_data[date_key] = {
                    'scores': [],
                    'dep_vulns': [],
                    'code_issues': []
                }
            
            daily_data[date_key]['scores'].append(scan.overall_risk_score)
            daily_data[date_key]['dep_vulns'].append(scan.dependency_vulnerabilities)
            daily_data[date_key]['code_issues'].append(scan.code_issues)
        
        trends = []
        for date, data in sorted(daily_data.items()):
            trends.append(RiskTrend(
                date=date,
                overall_risk_score=sum(data['scores']) / len(data['scores']),
                dependency_risk_score=sum(data['scores']) / len(data['scores']),  # Simplified
                code_risk_score=sum(data['scores']) / len(data['scores']),  # Simplified
                dependency_vulnerabilities=sum(data['dep_vulns']),
                code_issues=sum(data['code_issues'])
            ))
        
        return trends
    
    def get_dashboard_stats(self) -> DashboardStats:
        """Get dashboard statistics."""
        total_scans = self.db.query(ScanRecord).count()
        
        # Recent scans (last 7 days)
        since_date = datetime.utcnow() - timedelta(days=7)
        recent_scans = self.db.query(ScanRecord).filter(ScanRecord.scan_timestamp >= since_date).count()
        
        # Average risk score
        avg_risk = self.db.query(func.avg(ScanRecord.overall_risk_score)).scalar() or 0.0
        
        # High risk scans
        high_risk_scans = self.db.query(ScanRecord).filter(ScanRecord.overall_risk_score > 7.0).count()
        
        # Critical vulnerabilities
        critical_vulns = (self.db.query(ScanRecord)
                         .filter(ScanRecord.dependency_vulnerabilities > 0)
                         .count())
        
        # High severity code issues
        high_severity_issues = (self.db.query(ScanRecord)
                               .filter(ScanRecord.code_issues > 0)
                               .count())
        
        # Last scan date
        last_scan = (self.db.query(ScanRecord)
                    .order_by(desc(ScanRecord.scan_timestamp))
                    .first())
        
        return DashboardStats(
            total_scans=total_scans,
            recent_scans=recent_scans,
            average_risk_score=round(avg_risk, 2),
            high_risk_scans=high_risk_scans,
            critical_vulnerabilities=critical_vulns,
            high_severity_code_issues=high_severity_issues,
            last_scan_date=last_scan.scan_timestamp if last_scan else None
        )
    
    def get_scans_by_project(self, project_name: str, limit: int = 20) -> List[ScanSummary]:
        """Get scans for a specific project."""
        scans = (self.db.query(ScanRecord)
                .filter(ScanRecord.project_name == project_name)
                .order_by(desc(ScanRecord.scan_timestamp))
                .limit(limit)
                .all())
        
        return [
            ScanSummary(
                scan_id=scan.scan_id,
                target_path=scan.target_path,
                scan_timestamp=scan.scan_timestamp,
                overall_risk_score=scan.overall_risk_score,
                dependency_risk_score=scan.dependency_risk_score,
                code_risk_score=scan.code_risk_score,
                dependency_vulnerabilities=scan.dependency_vulnerabilities,
                code_issues=scan.code_issues,
                project_name=scan.project_name,
                branch_name=scan.branch_name,
                commit_hash=scan.commit_hash,
                success=scan.success
            )
            for scan in scans
        ]
