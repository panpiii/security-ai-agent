"""
FastAPI dashboard for security scan visualization and management.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from sqlalchemy.orm import Session

from ..database.database import db_manager
from ..database.repository import ScanRepository
from ..database.models import ScanSummary, ScanDetails, RiskTrend, DashboardStats
from ..scoring.risk_calculator import RiskCalculator

# Initialize FastAPI app
app = FastAPI(
    title="Security AI Agent Dashboard",
    description="Dashboard for visualizing security scan results and risk trends",
    version="1.0.0"
)

# Setup templates and static files
templates = Jinja2Templates(directory="secagent/dashboard/templates")
app.mount("/static", StaticFiles(directory="secagent/dashboard/static"), name="static")

# Template helper functions
def get_risk_class(score: float) -> str:
    """Get CSS class for risk score."""
    if score <= 3:
        return "risk-low"
    elif score <= 6:
        return "risk-medium"
    elif score <= 8:
        return "risk-high"
    else:
        return "risk-critical"

def format_timestamp(timestamp) -> str:
    """Format timestamp for display."""
    if hasattr(timestamp, 'strftime'):
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    return str(timestamp)

# Add template functions to Jinja2 environment
templates.env.globals.update({
    'getRiskClass': get_risk_class,
    'formatTimestamp': format_timestamp
})

# Dependency to get database session
def get_db():
    db = next(db_manager.get_session())
    try:
        yield db
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request, db: Session = Depends(get_db)):
    """Main dashboard page."""
    repo = ScanRepository(db)
    stats = repo.get_dashboard_stats()
    recent_scans = repo.get_recent_scans(limit=10)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "recent_scans": recent_scans,
        "getRiskClass": get_risk_class,
        "formatTimestamp": format_timestamp
    })


@app.get("/api/stats", response_model=DashboardStats)
async def get_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics."""
    repo = ScanRepository(db)
    return repo.get_dashboard_stats()


@app.get("/api/scans", response_model=List[ScanSummary])
async def get_scans(
    limit: int = Query(50, ge=1, le=100),
    project: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Get recent scans."""
    repo = ScanRepository(db)
    
    if project:
        return repo.get_scans_by_project(project, limit)
    else:
        return repo.get_recent_scans(limit)


@app.get("/api/scans/{scan_id}", response_model=ScanDetails)
async def get_scan_details(scan_id: str, db: Session = Depends(get_db)):
    """Get detailed scan information."""
    repo = ScanRepository(db)
    scan = repo.get_scan_by_id(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan


@app.get("/api/trends", response_model=List[RiskTrend])
async def get_risk_trends(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db)
):
    """Get risk trends over time."""
    repo = ScanRepository(db)
    return repo.get_risk_trends(days)


@app.get("/api/projects")
async def get_projects(db: Session = Depends(get_db)):
    """Get list of projects that have been scanned."""
    repo = ScanRepository(db)
    # This would need to be implemented in the repository
    # For now, return empty list
    return []


@app.post("/api/scans/{scan_id}/recalculate-risk")
async def recalculate_risk(scan_id: str, db: Session = Depends(get_db)):
    """Recalculate risk score for a specific scan."""
    from ..database.models import ScanRecord
    
    repo = ScanRepository(db)
    scan = repo.get_scan_by_id(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Recalculate risk score
    calculator = RiskCalculator()
    risk_score = calculator.calculate_risk_score(scan.scan_results)
    
    # Update the scan record
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if scan_record:
        scan_record.overall_risk_score = risk_score.overall_score
        scan_record.dependency_risk_score = risk_score.dependency_risk
        scan_record.code_risk_score = risk_score.code_risk
        scan_record.risk_factors = risk_score.factors
        scan_record.recommendations = risk_score.recommendations
        db.commit()
    
    return {"message": "Risk score recalculated", "new_score": risk_score.overall_score}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    import uvicorn
    
    # Create database tables
    db_manager.create_tables()
    
    # Run the dashboard
    uvicorn.run(
        "secagent.dashboard.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
