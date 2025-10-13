import json
from pathlib import Path

# Directory where the output files are
output_dir = Path("examples/output")

# Files to compare
files = [
    output_dir / "sample_combined.json",
    output_dir / "sample_combined2.json",
    output_dir / "sample_pip_only.json"
]

# Extract summaries from each report
summaries = {}
for f in files:
    if f.exists():
        with open(f, "r", encoding="utf-8") as file:
            data = json.load(file)
            summaries[f.name] = data.get("summary", {})

# Build CSV lines
comparison_lines = ["File,Dependency Vulnerabilities,Code Issues"]
for name, summary in summaries.items():
    comparison_lines.append(
        f"{name},{summary.get('dependency_vulnerabilities', 0)},{summary.get('code_issues', 0)}"
    )

# Write CSV
output_path = output_dir / "summary_comparison.csv"
output_path.write_text("\n".join(comparison_lines), encoding="utf-8")

print(f"✅ Summary comparison saved to: {output_path}")
