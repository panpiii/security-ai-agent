from __future__ import annotations
from typing import Literal, Dict, Any

SummaryFormat = Literal["md", "json"]

class Summarizer:
    def summarize(self, data: Dict[str, Any], out_format: SummaryFormat = "md") -> str:
        raise NotImplementedError
