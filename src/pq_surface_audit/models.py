from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceObservation:
    service: str
    status: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AssetResult:
    target: str
    hostname: str
    port: int | None
    observations: list[ServiceObservation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    priority: str = "low"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "hostname": self.hostname,
            "port": self.port,
            "observations": [o.to_dict() for o in self.observations],
            "findings": [f.to_dict() for f in self.findings],
            "score": self.score,
            "priority": self.priority,
            "notes": self.notes,
        }


@dataclass
class ScanReport:
    generated_at: str
    assets: list[AssetResult]
    summary: dict[str, Any]
    tool: str = "pq-surface-audit"
    version: str = "0.1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "generated_at": self.generated_at,
            "summary": self.summary,
            "assets": [asset.to_dict() for asset in self.assets],
        }
