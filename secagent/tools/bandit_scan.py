import json
import subprocess
from pathlib import Path
from typing import Tuple, Any, Dict

def run_bandit(target: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Run Bandit static analysis on the given directory or file.

    Returns:
        (results, meta): Parsed JSON results and metadata.
    """
    cmd = ["bandit", "-r", str(target), "-f", "json"]
    process = subprocess.run(cmd, capture_output=True, text=True)
    meta = {
        "exit_code": process.returncode,
        "args": cmd,
        "stderr": process.stderr.strip(),
    }

    try:
        results = json.loads(process.stdout or "{}")
    except json.JSONDecodeError:
        results = {"error": "Failed to parse Bandit output"}

    return results, meta
