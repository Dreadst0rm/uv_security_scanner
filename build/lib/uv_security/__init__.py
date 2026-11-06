"""uv-security: scan-friendly security scanner for uv projects."""

from .models import (
    Severity,
    Vulnerability,
    ProjectResult,
    VenvResult,
    ScanSummary,
    ScanResult,
)
from .parser import parse_uv_audit, parse_vulnerability_count
from .scanner import scan_root
from .report import write_json_report, write_html_report
from .upgrade import upgrade_package, preview_upgrade

__all__ = [
    "Severity",
    "Vulnerability",
    "ProjectResult",
    "VenvResult",
    "ScanSummary",
    "ScanResult",
    "parse_uv_audit",
    "parse_vulnerability_count",
    "scan_root",
    "write_json_report",
    "write_html_report",
    "upgrade_package",
    "preview_upgrade",
]

__version__ = "1.0.0"
