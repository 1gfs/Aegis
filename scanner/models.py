"""Data models for scan results."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class Finding:
    """A single security finding from a check."""

    title: str
    severity: Severity
    description: str
    category: str
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "category": self.category,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanResult:
    """Complete results from scanning a target."""

    target: str
    started_at: datetime
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "highest_severity": self.highest_severity.value,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
