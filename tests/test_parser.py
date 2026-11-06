"""Tests for uv_security.parser."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from uv_security.parser import parse_uv_audit, parse_vulnerability_count


SAMPLE_OUTPUT = """
Found 11 known vulnerabilities and no adverse project statuses
Vulnerabilities:

requests 2.28.0 has 4 known vulnerabilities:

- PYSEC-2026-2275: Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function

  Fixed in: 2.33.0

  Advisory information: https://nvd.nist.gov/vuln/detail/CVE-2026-25645

- PYSEC-2026-1873: Requests `Session` object does not verify requests after making first request with verify=False

  Fixed in: 2.32.0

  Advisory information: https://nvd.nist.gov/vuln/detail/CVE-2024-35195

urllib3 1.26.20 has 7 known vulnerabilities:

- PYSEC-2026-4177: urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory

  Fixed in: 2.8.0

  Advisory information: https://nvd.nist.gov/vuln/detail/CVE-2026-97689
"""


def test_parse_count():
    assert parse_vulnerability_count(SAMPLE_OUTPUT) == 11


def test_parse_vulnerabilities():
    vulns = parse_uv_audit(SAMPLE_OUTPUT)
    assert len(vulns) == 3

    by_pkg = {}
    for v in vulns:
        by_pkg.setdefault(v.package, []).append(v)

    assert len(by_pkg["requests"]) == 2
    assert len(by_pkg["urllib3"]) == 1

    r = by_pkg["requests"][0]
    assert r.package == "requests"
    assert r.installed_version == "2.28.0"
    assert r.fixed_version == "2.33.0"
    assert r.advisory_id == "PYSEC-2026-2275"
    assert "Insecure Temp File Reuse" in r.summary
    assert r.advisory_url == "https://nvd.nist.gov/vuln/detail/CVE-2026-25645"


def test_empty_output():
    assert parse_uv_audit("") == []
    assert parse_vulnerability_count("") is None


def test_no_vulnerabilities():
    out = "Found 0 known vulnerabilities and no adverse project statuses\nVulnerabilities:\n"
    assert parse_vulnerability_count(out) == 0
    assert parse_uv_audit(out) == []
