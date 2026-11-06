"""Data models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class Severity:
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNSCORED = "Unscored"


@dataclass
class Vulnerability:
    """A single vulnerability reported by ``uv audit``."""

    package: str
    installed_version: str
    fixed_version: Optional[str]
    advisory_id: str
    summary: str
    advisory_url: Optional[str]
    severity: str = "Unscored"
    cvss: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "advisory_id": self.advisory_id,
            "summary": self.summary,
            "advisory_url": self.advisory_url,
            "severity": self.severity,
            "cvss": self.cvss,
        }


@dataclass
class ProjectResult:
    """Result for one uv project (a directory containing uv.lock)."""

    path: str
    lock_status: str  # PASS / WARN
    lock_detail: str
    audit_status: str  # PASS / VULNERABLE / WARN
    audit_detail: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "lock_status": self.lock_status,
            "lock_detail": self.lock_detail,
            "audit_status": self.audit_status,
            "audit_detail": self.audit_detail,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }

    @property
    def vuln_count(self) -> int:
        return len(self.vulnerabilities)


@dataclass
class VenvResult:
    """Result for one virtual environment."""

    path: str
    python_version: Optional[str]
    pip_check_status: str  # PASS / WARN
    pip_check_detail: str

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "python_version": self.python_version,
            "pip_check_status": self.pip_check_status,
            "pip_check_detail": self.pip_check_detail,
        }


@dataclass
class ScanSummary:
    projects: int = 0
    venvs: int = 0
    vulnerable_projects: int = 0
    total_vulnerabilities: int = 0
    lock_problems: int = 0
    env_problems: int = 0

    @property
    def has_issues(self) -> bool:
        return (
            self.vulnerable_projects > 0
            or self.lock_problems > 0
            or self.env_problems > 0
        )


@dataclass
class ScanResult:
    """Complete scan result."""

    root: str
    timestamp: str
    projects: List[ProjectResult] = field(default_factory=list)
    venvs: List[VenvResult] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "timestamp": self.timestamp,
            "summary": {
                "projects": self.summary.projects,
                "venvs": self.summary.venvs,
                "vulnerable_projects": self.summary.vulnerable_projects,
                "total_vulnerabilities": self.summary.total_vulnerabilities,
                "lock_problems": self.summary.lock_problems,
                "env_problems": self.summary.env_problems,
            },
            "projects": [p.to_dict() for p in self.projects],
            "venvs": [v.to_dict() for v in self.venvs],
        }
