"""
Automatic risk scoring for security scan results.
"""
from __future__ import annotations

import math
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass


@dataclass
class RiskScore:
    """Risk score breakdown and details."""
    overall_score: float  # 0-10 scale
    dependency_risk: float
    code_risk: float
    factors: Dict[str, Any]
    recommendations: List[str]


class RiskCalculator:
    """Calculates risk scores based on scan results."""
    
    # Severity weights for different types of issues
    SEVERITY_WEIGHTS = {
        "CRITICAL": 10.0,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 2.0,
        "INFO": 0.5,
    }
    
    # CVE severity mapping
    CVE_SEVERITY_MAP = {
        "CRITICAL": 10.0,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 2.0,
    }
    
    def __init__(self):
        self.base_risk_threshold = 3.0  # Minimum risk to be considered significant
    
    def calculate_risk_score(self, scan_data: Dict[str, Any]) -> RiskScore:
        """
        Calculate comprehensive risk score from scan results.
        
        Args:
            scan_data: Combined scan results from agent
            
        Returns:
            RiskScore object with detailed breakdown
        """
        results = scan_data.get("results", {})
        summary = scan_data.get("summary", {})
        
        # Calculate dependency risk
        dep_risk, dep_factors = self._calculate_dependency_risk(results.get("pip_audit", {}))
        
        # Calculate code risk
        code_risk, code_factors = self._calculate_code_risk(results.get("bandit", {}))
        
        # Calculate overall risk (weighted average with dependency risk slightly higher)
        overall_score = (dep_risk * 0.6) + (code_risk * 0.4)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(dep_risk, code_risk, dep_factors, code_factors)
        
        return RiskScore(
            overall_score=round(overall_score, 2),
            dependency_risk=round(dep_risk, 2),
            code_risk=round(code_risk, 2),
            factors={
                "dependency_factors": dep_factors,
                "code_factors": code_factors,
                "total_dependencies": len(results.get("pip_audit", {}).get("dependencies", [])),
                "total_code_issues": len(results.get("bandit", {}).get("results", [])),
            },
            recommendations=recommendations
        )
    
    def _calculate_dependency_risk(self, pip_audit_results: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """Calculate risk score for dependency vulnerabilities."""
        dependencies = pip_audit_results.get("dependencies", [])
        fixes = pip_audit_results.get("fixes", [])
        
        total_risk = 0.0
        vuln_count = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for dep in dependencies:
            vulns = dep.get("vulns", [])
            for vuln in vulns:
                vuln_count += 1
                
                # Extract severity from CVE data
                severity = self._extract_cve_severity(vuln)
                weight = self.CVE_SEVERITY_MAP.get(severity, 2.0)
                
                # Apply severity-based risk calculation
                risk_contribution = weight * self._calculate_vuln_risk_multiplier(vuln)
                total_risk += risk_contribution
                
                # Count by severity
                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "HIGH":
                    high_count += 1
                elif severity == "MEDIUM":
                    medium_count += 1
                else:
                    low_count += 1
        
        # Normalize risk score (0-10 scale)
        normalized_risk = min(total_risk / max(len(dependencies), 1) * 2, 10.0)
        
        factors = {
            "vulnerability_count": vuln_count,
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "medium_vulnerabilities": medium_count,
            "low_vulnerabilities": low_count,
            "available_fixes": len(fixes),
            "dependencies_scanned": len(dependencies),
        }
        
        return normalized_risk, factors
    
    def _calculate_code_risk(self, bandit_results: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """Calculate risk score for code security issues."""
        findings = bandit_results.get("results", [])
        
        total_risk = 0.0
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for finding in findings:
            severity = finding.get("issue_severity", "LOW")
            confidence = finding.get("issue_confidence", "LOW")
            test_id = finding.get("test_id", "")
            
            # Base risk from severity
            severity_weight = self.SEVERITY_WEIGHTS.get(severity, 2.0)
            
            # Confidence multiplier
            confidence_multiplier = self.SEVERITY_WEIGHTS.get(confidence, 2.0) / 10.0
            
            # Test-specific risk adjustments
            test_risk_multiplier = self._get_test_risk_multiplier(test_id)
            
            risk_contribution = severity_weight * confidence_multiplier * test_risk_multiplier
            total_risk += risk_contribution
            
            # Count by severity and confidence
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
        
        # Normalize risk score (0-10 scale)
        normalized_risk = min(total_risk / max(len(findings), 1) * 3, 10.0)
        
        factors = {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "confidence_breakdown": confidence_counts,
            "high_severity_issues": severity_counts.get("HIGH", 0),
            "medium_severity_issues": severity_counts.get("MEDIUM", 0),
        }
        
        return normalized_risk, factors
    
    def _extract_cve_severity(self, vuln: Dict[str, Any]) -> str:
        """Extract severity from CVE vulnerability data."""
        # Try to get severity from various possible fields
        severity_fields = ["severity", "cvss_score", "severity_score"]
        
        for field in severity_fields:
            if field in vuln:
                severity = vuln[field]
                if isinstance(severity, (int, float)):
                    # Convert numeric score to severity level
                    if severity >= 9.0:
                        return "CRITICAL"
                    elif severity >= 7.0:
                        return "HIGH"
                    elif severity >= 4.0:
                        return "MEDIUM"
                    else:
                        return "LOW"
                elif isinstance(severity, str):
                    return severity.upper()
        
        # Default to MEDIUM if no severity found
        return "MEDIUM"
    
    def _calculate_vuln_risk_multiplier(self, vuln: Dict[str, Any]) -> float:
        """Calculate additional risk multiplier for specific vulnerability characteristics."""
        multiplier = 1.0
        
        # Check if fix is available
        fix_versions = vuln.get("fix_versions", [])
        if not fix_versions:
            multiplier *= 1.5  # No fix available increases risk
        
        # Check for multiple aliases (indicates well-known vulnerability)
        aliases = vuln.get("aliases", [])
        if len(aliases) > 2:
            multiplier *= 1.2  # Multiple aliases indicate widespread issue
        
        return multiplier
    
    def _get_test_risk_multiplier(self, test_id: str) -> float:
        """Get risk multiplier based on specific Bandit test."""
        # High-risk tests get higher multipliers
        high_risk_tests = {
            "B105",  # hardcoded_password_string
            "B106",  # hardcoded_password_funcarg
            "B107",  # hardcoded_password_default
            "B602",  # subprocess_popen_with_shell_equals_true
            "B603",  # subprocess_without_shell_equals_true
            "B608",  # hardcoded_sql_expressions
        }
        
        medium_risk_tests = {
            "B101",  # assert_used
            "B102",  # exec_used
            "B201",  # flask_debug_true
            "B301",  # pickle
            "B302",  # marshal
        }
        
        if test_id in high_risk_tests:
            return 1.5
        elif test_id in medium_risk_tests:
            return 1.2
        else:
            return 1.0
    
    def _generate_recommendations(self, dep_risk: float, code_risk: float, 
                                dep_factors: Dict[str, Any], code_factors: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on risk analysis."""
        recommendations = []
        
        # Dependency recommendations
        if dep_risk > 5.0:
            recommendations.append("🚨 HIGH PRIORITY: Address critical dependency vulnerabilities immediately")
        elif dep_risk > 3.0:
            recommendations.append("⚠️ MEDIUM PRIORITY: Update vulnerable dependencies")
        
        if dep_factors.get("critical_vulnerabilities", 0) > 0:
            recommendations.append("🔴 CRITICAL: Fix critical vulnerabilities before deployment")
        
        if dep_factors.get("available_fixes", 0) > 0:
            recommendations.append("✅ Updates available: Run 'pip install --upgrade' for affected packages")
        
        # Code recommendations
        if code_risk > 5.0:
            recommendations.append("🔍 HIGH PRIORITY: Review and fix high-severity code issues")
        elif code_risk > 3.0:
            recommendations.append("📝 MEDIUM PRIORITY: Address code security issues")
        
        if code_factors.get("high_severity_issues", 0) > 0:
            recommendations.append("🔴 CRITICAL: Fix high-severity code issues before merge")
        
        # General recommendations
        if dep_risk + code_risk > 7.0:
            recommendations.append("🛡️ SECURITY REVIEW: Consider security team review before release")
        
        if not recommendations:
            recommendations.append("✅ No immediate security concerns detected")
        
        return recommendations
