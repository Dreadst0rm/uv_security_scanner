"""Parsers for ``uv audit --preview`` output.

Real ``uv audit`` output looks like::

    Found 11 known vulnerabilities and no adverse project statuses
    Vulnerabilities:

    requests 2.28.0 has 4 known vulnerabilities:

    - PYSEC-2026-2275: Requests has Insecure Temp File Reuse ...

      Fixed in: 2.33.0

      Advisory information: https://nvd.nist.gov/vuln/detail/CVE-2026-25645

    urllib3 1.26.20 has 7 known vulnerabilities:
    ...
"""

from __future__ import annotations

import re
from typing import List, Optional
from .models import Vulnerability

# "Found 11 known vulnerabilities ..."
_COUNT_RE = re.compile(r"Found\s+(\d+)\s+known vulnerabilit", re.IGNORECASE)

# "requests 2.28.0 has 4 known vulnerabilities:"
_PKG_HEADER_RE = re.compile(
    r"^(?P<package>\S+)\s+(?P<version>\S+)\s+has\s+\d+\s+known vulnerabilities:\s*$",
    re.IGNORECASE,
)

# "- PYSEC-2026-2275: Requests has ..."
_ADVISORY_RE = re.compile(r"^-\s*(?P<advisory_id>\S+):\s*(?P<summary>.*)$", re.IGNORECASE)

# "  Fixed in: 2.33.0"
_FIXED_RE = re.compile(r"^\s*Fixed in:\s*(?P<version>\S+)\s*$", re.IGNORECASE)

# "  Advisory information: https://..."
_URL_RE = re.compile(
    r"^\s*Advisory information:\s*(?P<url>\S+)\s*$", re.IGNORECASE
)


def parse_vulnerability_count(output: str) -> Optional[int]:
    """Return the total vulnerability count from ``uv audit`` output, or None."""
    m = _COUNT_RE.search(output)
    if not m:
        return None
    return int(m.group(1))


def parse_uv_audit(output: str) -> List[Vulnerability]:
    """Parse ``uv audit --preview`` output into a list of :class:`Vulnerability`.

    The parser is defensive: unrecognised lines are skipped so that minor
    output changes across ``uv`` versions do not crash the scanner.
    """
    vulns: List[Vulnerability] = []
    lines = output.splitlines()

    current_package: Optional[str] = None
    current_version: Optional[str] = None
    current_advisory_id: Optional[str] = None
    current_summary: Optional[str] = None
    current_fixed: Optional[str] = None
    current_url: Optional[str] = None

    def flush() -> None:
        nonlocal current_package, current_version, current_advisory_id
        nonlocal current_summary, current_fixed, current_url
        if current_package and current_advisory_id:
            vulns.append(
                Vulnerability(
                    package=current_package,
                    installed_version=current_version or "unknown",
                    fixed_version=current_fixed,
                    advisory_id=current_advisory_id,
                    summary=current_summary or "",
                    advisory_url=current_url,
                )
            )
        current_advisory_id = None
        current_summary = None
        current_fixed = None
        current_url = None

    for line in lines:
        line = line.rstrip("\n")

        m = _PKG_HEADER_RE.match(line)
        if m:
            flush()
            current_package = m.group("package")
            current_version = m.group("version")
            continue

        m = _ADVISORY_RE.match(line)
        if m:
            flush()
            current_advisory_id = m.group("advisory_id")
            current_summary = m.group("summary")
            continue

        m = _FIXED_RE.match(line)
        if m:
            current_fixed = m.group("version")
            continue

        m = _URL_RE.match(line)
        if m:
            current_url = m.group("url")
            continue

    flush()
    return vulns
