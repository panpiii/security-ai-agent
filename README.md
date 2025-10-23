# 🔒 Security AI Agent
> 🧠 *A lightweight DevSecOps CLI that runs pip-audit + Bandit and summarizes security results with AI.*

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)]()
[![Status](https://img.shields.io/badge/status-MVP-orange)]()

A lightweight **DevSecOps command-line tool** that orchestrates open-source security scanners and uses AI to summarize findings into human-readable risk reports with an interactive dashboard.

---

## 🚀 Overview

**Security AI Agent** helps developers and DevOps engineers quickly identify vulnerabilities in their Python projects.

It runs open-source scanners and produces consolidated reports:
- 🧩 [`pip-audit`](https://pypi.org/project/pip-audit/) — dependency vulnerability scanning  
- 🧱 [`Bandit`](https://pypi.org/project/bandit/) — static code analysis for insecure coding patterns  
- 🤖 **AI Risk Scoring** — automatic risk assessment with actionable recommendations
- 📊 **Interactive Dashboard** — web interface for visualizing security trends and history  

### 💡 Why this project
Modern teams ship fast, but often skip security checks until deployment.  
This tool automates early detection by integrating lightweight scans into your **local workflow** or **CI/CD pipeline**, keeping your dependencies and code secure from the start.

---

## 🛠️ Features

| Feature | Description |
|----------|-------------|
| 🔍 Dependency scanning | Audits Python dependencies for known CVEs using `pip-audit` |
| 🧱 Code scanning | Detects unsafe coding patterns with `Bandit` |
| 🎯 **Automatic Risk Scoring** | AI-powered risk assessment (0-10 scale) with smart recommendations |
| 📊 **Interactive Dashboard** | Web interface with charts, trends, and historical analysis |
| 🗄️ **Database Storage** | Persistent scan history with project/branch tracking |
| 🧾 JSON & Markdown output | Generates structured reports for humans or automation |
| 🎨 Beautiful CLI | Built with `Typer` and `Rich` for modern UX |
| 🧠 AI summarization | Uses LLMs (OpenAI) to summarize and prioritize risks |

---

## 🧰 Tech Stack

- **Language:** Python 3.11+
- **CLI Framework:** [Typer](https://typer.tiangolo.com/)
- **UI Library:** [Rich](https://github.com/Textualize/rich)
- **Web Framework:** [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/)
- **Database:** [SQLAlchemy](https://www.sqlalchemy.org/) (SQLite/PostgreSQL)
- **Schema/Validation:** [Pydantic](https://docs.pydantic.dev/)
- **Security Tools:** `pip-audit`, `Bandit`
- **LLM Integration:** OpenAI / Anthropic APIs
- **Use Case:** DevSecOps, Cloud, and Backend automation pipelines

---

## 🧪 Installation (Development)

```bash
# Clone the repository
git clone https://github.com/panpiii/security-ai-agent.git
cd security-ai-agent

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

## ⚡ Usage
### A) Run combined scan (pip-audit + Bandit)
```
sec-agent scan --target secagent -o examples/output/combined.json
```

### B) Deterministic dependency scan (recommended for CI)

Create a requirements.txt with your app dependencies (not dev tools):

```
cat > requirements.txt << 'EOF'
typer>=0.12.3
rich>=13.7.1
pydantic>=2.8.2
EOF
```


Then (optionally add dev tools):

```
cat > dev-requirements.txt << 'EOF'
pip-audit>=2.7.3
bandit>=1.7.9
EOF

pip install -r requirements.txt -r dev-requirements.txt
sec-agent scan -r requirements.txt -o examples/output/sample_pip_only.json
```

### C) Quick human summary (optional)
```
sec-agent scan --target secagent --summary
```


Prints a short panel like:
```
Summary
Dependency vulns: 1
Code issues: 0
Target: /Users/teresapan/security-ai-agent
```

### D) 🎯 **NEW: Risk Scoring & Dashboard**

**Run scan with automatic risk scoring:**
```bash
sec-agent scan --target . --store --project "my-app" --branch "main"
```

**Start the interactive dashboard:**
```bash
sec-agent dashboard
# Visit http://localhost:8000
```

**Features:**
- 🎯 **Automatic Risk Scoring** (0-10 scale)
- 📊 **Interactive Dashboard** with charts and trends
- 🗄️ **Database Storage** for historical analysis
- 🤖 **AI Recommendations** for remediation

### E) Compare multiple reports

Generate a CSV comparing summaries across runs:
```
python tools/compare_summaries.py
cat examples/output/summary_comparison.csv
```


Example output:

```
File,Dependency Vulnerabilities,Code Issues
combined.json,3,4
combined2.json,1,0
sample_pip_only.json,0,0
```

📊 Results Snapshot (Example)

|Scan	| Dependency vulns	| Bandit issues |	Notes
|----- | -----| --------|------|
| combined.json	| 3	|4	|Initial run on full venv|
| combined2.json | 1|0	|After upgrading setuptools to >=78.1.1|
| sample_pip_only.json	| 0 | 	—	| Scanning only project deps via -r requirements.txt|


#### Remaining item: pip advisory (fix planned for version 25.3+). Re-run after upgrading pip when available.

# 🧩 Example JSON Output (Trimmed)
```
{
  "tool": "security-ai-agent",
  "meta": {
    "generated_by": "sec-agent",
    "scanners": {
      "pip_audit": {"finding_count": 1},
      "bandit": {"finding_count": 0}
    }
  },
  "summary": {
    "dependency_vulnerabilities": 1,
    "code_issues": 0
  }
}
```

### 🔐 Notes on Bandit Findings

This project uses `subprocess` to invoke scanners.
Calls are **safe by design** (no shell, fixed argv).
Low-severity Bandit rules (B404/B603) may appear as reminders; they’re explicitly justified with inline `# nosec `comments.

### E) AI Summary (with mock provider for demos)

Generate an ***AI-style Markdown summary*** (no API calls, perfect for screenshots or CI):
```
sec-agent scan --target secagent -o examples/output/combined.json \
  --with-llm --llm-provider openai --llm-model gpt-4o-mini
--summary-format md \
  --summary-output examples/output/combined_llm.md
```

## AI Summary Preview (Mock Example)
![AI Summary Preview](/security-ai-agent/assets/MockMDSummary%20.PNG)

### 🧭 Roadmap

* ✅ MVP: Run pip-audit and Bandit, export combined JSON

* ✅ Integrate LLM summarizer (Now: OpenAI)

- 🔜 Add --scanners flag to toggle tools

+ 🔜 GitHub Action: run on pull requests

+ 🔜 FastAPI dashboard for historical scans

### 🧑‍💻 Author

Developed by **Teresa Pan**
Early-career**DevSecOps / Cloud Engineer** passionate about automation, clean tooling, and developer security culture.

### 📄 License

MIT License — see LICENSE
 for details.