#!/usr/bin/env python3
"""
Demo script showing the new risk scoring and dashboard features.
"""
import subprocess
import time
import json
from pathlib import Path


def run_scan_with_risk_scoring():
    """Run a scan with risk scoring enabled."""
    print("🔒 Running Security Scan with Risk Scoring...")
    
    cmd = [
        "sec-agent", "scan",
        "--target", ".",
        "--output", "examples/output/demo_scan.json",
        "--store",  # Store in database
        "--project", "security-ai-agent",
        "--branch", "main"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=".")
        print("✅ Scan completed!")
        print("STDOUT:", result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except FileNotFoundError:
        print("❌ sec-agent command not found. Make sure it's installed.")
        return False


def start_dashboard():
    """Start the dashboard server."""
    print("\n📊 Starting Security Dashboard...")
    print("Dashboard will be available at: http://localhost:8000")
    print("Press Ctrl+C to stop the dashboard")
    
    try:
        subprocess.run([
            "sec-agent", "dashboard",
            "--host", "127.0.0.1",
            "--port", "8000"
        ])
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped.")
    except FileNotFoundError:
        print("❌ sec-agent command not found. Make sure it's installed.")


def show_scan_results():
    """Display the scan results."""
    results_file = Path("examples/output/demo_scan.json")
    if not results_file.exists():
        print("❌ No scan results found.")
        return
    
    with open(results_file) as f:
        data = json.load(f)
    
    print("\n📊 Scan Results Summary:")
    print(f"Target: {data.get('target', 'Unknown')}")
    
    risk_score = data.get('risk_score', {})
    if risk_score:
        overall = risk_score.get('overall', 0)
        dep_risk = risk_score.get('dependency', 0)
        code_risk = risk_score.get('code', 0)
        
        print(f"Overall Risk Score: {overall}/10")
        print(f"Dependency Risk: {dep_risk}/10")
        print(f"Code Risk: {code_risk}/10")
        
        recommendations = risk_score.get('recommendations', [])
        if recommendations:
            print("\n💡 Recommendations:")
            for rec in recommendations:
                print(f"  • {rec}")
    
    summary = data.get('summary', {})
    print(f"\nDependency Vulnerabilities: {summary.get('dependency_vulnerabilities', 0)}")
    print(f"Code Issues: {summary.get('code_issues', 0)}")


def main():
    """Main demo function."""
    print("🚀 Security AI Agent - Risk Scoring & Dashboard Demo")
    print("=" * 60)
    
    # Create output directory
    Path("examples/output").mkdir(parents=True, exist_ok=True)
    
    # Run scan
    if run_scan_with_risk_scoring():
        show_scan_results()
        
        print("\n" + "=" * 60)
        print("🎯 Next Steps:")
        print("1. View the dashboard at http://localhost:8000")
        print("2. Run multiple scans to see trends")
        print("3. Check the database for historical data")
        
        # Ask if user wants to start dashboard
        response = input("\nStart the dashboard now? (y/n): ").lower().strip()
        if response in ['y', 'yes']:
            start_dashboard()
    else:
        print("❌ Scan failed. Please check your setup.")


if __name__ == "__main__":
    main()
