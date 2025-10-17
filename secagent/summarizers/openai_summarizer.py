from __future__ import annotations
import os
import json
from typing import Dict, Any, Literal

from .base import Summarizer, SummaryFormat

# Uses the "Responses" API if available in your openai package; falls back to ChatCompletions if not.
USE_RESPONSES = True

class OpenAISummarizer(Summarizer):
    def __init__(self, model: str = "gpt-4o-mini"):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set.")
        self.model = model
        # lazy import to avoid hard dep if not used
        try:
            from openai import OpenAI  # type: ignore
            self._client = OpenAI(api_key=api_key)
            self._mode = "responses"
        except Exception:
            # fallback (older SDKs)
            import openai  # type: ignore
            openai.api_key = api_key
            self._client = openai
            self._mode = "chat"

    def summarize(self, data: Dict[str, Any], out_format: SummaryFormat = "md") -> str:
        # Trim data to what LLM needs (keeps token cost low)
        trimmed = _extract_minimal(data)

        system = (
            "You are a senior AppSec engineer. Write concise, high-signal security reports.\n"
            "Prioritize: top risks, business impact, concrete fixes, upgrade pins.\n"
            "Assume audience is developers and DevOps. Avoid alarmism. Be actionable."
        )

        user_md = (
            f"Produce a {out_format.upper()} summary of these scan results.\n"
            "Include:\n"
            "1) Overall risk score (0-10) and rationale\n"
            "2) Top issues grouped by dependency vs code\n"
            "3) Concrete remediation steps (pin versions, code changes)\n"
            "4) Short checklist to merge safely\n"
            "Keep it under ~250-300 words if MD. If JSON, return an object with fields:\n"
            "{risk_score, overview, dependencies[{name,version,issues[{id,fix_versions}]}], "
            "code_issues[{file,line,test_id,severity,advice}], remediation[{type,action}], checklist[]}\n"
            f"\nDATA:\n```json\n{json.dumps(trimmed, indent=2)}\n```"
        )

        if self._mode == "responses":
            # Newer SDK
            resp = self._client.responses.create(
                model=self.model,
                input=[{"role": "system", "content": system},
                       {"role": "user", "content": user_md}]
            )
            content = resp.output_text  # type: ignore[attr-defined]
        else:
            # Older ChatCompletions
            resp = self._client.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user_md}],
                temperature=0.2,
            )
            content = resp["choices"][0]["message"]["content"]

        return content.strip()


def _extract_minimal(full: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce to what the LLM needs: counts + only vulnerable deps + bandit findings."""
    results = full.get("results", {})
    pa = results.get("pip_audit", {})
    bandit = results.get("bandit", {})
    deps = pa.get("dependencies", [])
    vuln_deps = []
    for d in deps:
        vulns = [v for v in d.get("vulns", [])]
        if vulns:
            vuln_deps.append({
                "name": d.get("name"),
                "version": d.get("version"),
                "vulns": [
                    {"id": v.get("id"),
                     "aliases": v.get("aliases"),
                     "fix_versions": v.get("fix_versions")}
                    for v in vulns
                ],
            })

    bandit_findings = []
    for r in bandit.get("results", []):
        bandit_findings.append({
            "file": r.get("filename"),
            "line": r.get("line_number"),
            "test_id": r.get("test_id"),
            "severity": r.get("issue_severity"),
            "confidence": r.get("issue_confidence"),
            "text": r.get("issue_text"),
        })

    return {
        "summary": full.get("summary", {}),
        "target": full.get("target"),
        "vulnerable_dependencies": vuln_deps,
        "bandit_findings": bandit_findings,
    }
