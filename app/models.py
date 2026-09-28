from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class Finding:
    severity: str
    file: str
    line: int
    snippet: str
    rule: str
    explanation: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class FileResult:
    path: str
    file_type: str
    size: int
    sha256: str
    status: str
    reason: str | None = None
    findings: list[Finding] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in (self.findings or [])]
        return data
