from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple, Any, Dict


def _find_requirements(target: Path) -> Optional[Path]:
    candidate = target / "requirements.txt"
    return candidate if candidate.exists() else None


def run_pip_audit(
    target: Path, requirements: Optional[Path] = None
) -> Tuple[Any, Dict[str, Any]]:
    """
    Runs `pip-audit` via subprocess, returns (results_json, meta_dict).
    """
    if not shutil.which("pip-audit"):
        raise RuntimeError(
            "pip-audit is not installed or not on PATH. "
            "Install it with: pip install pip-audit"
        )

    args = ["pip-audit", "-f", "json"]
    req = requirements or _find_requirements(target)

    if req:
        args += ["-r", str(req)]

    proc = subprocess.run(args, capture_output=True, text=True)
    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    parsed = []
    if stdout:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse pip-audit JSON: {e}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")

    meta = {
        "exit_code": proc.returncode,
        "stderr": stderr,
        "args": args,
        "mode": "requirements" if req else "environment",
        "requirements": str(req) if req else None,
    }
    return parsed, meta
