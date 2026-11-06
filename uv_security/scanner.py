"""Scan orchestration: discovery, parallel auditing, venv checks."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional, Tuple

from .models import (
    ProjectResult,
    VenvResult,
    ScanResult,
    ScanSummary,
    Vulnerability,
)
from .parser import parse_uv_audit, parse_vulnerability_count
from .cache import Cache


def _run(cmd: List[str], cwd: Optional[str] = None) -> Tuple[int, str]:
    """Run a command, returning (exit_code, combined_output)."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, output.strip()
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, str(exc)


def _lock_hash(path: str) -> str:
    """Stable hash of a uv.lock file for cache invalidation."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return "missing"
    return h.hexdigest()


def _audit_lock(project: str) -> Tuple[str, str]:
    """Run ``uv lock --check``. Returns (status, detail)."""
    code, output = _run(["uv", "lock", "--check"], cwd=project)
    if code == 0:
        return "PASS", "uv.lock matches project metadata"
    return "WARN", output or "uv.lock check failed"


def _audit_vulnerabilities(project: str) -> Tuple[str, str, List[Vulnerability]]:
    """Run ``uv --preview audit``. Returns (status, detail, vulnerabilities)."""
    code, output = _run(["uv", "--preview", "audit"], cwd=project)
    count = parse_vulnerability_count(output)
    vulns = parse_uv_audit(output)

    if vulns:
        return "VULNERABLE", f"uv audit found {len(vulns)} known vulnerabilities", vulns
    if count is not None and count > 0:
        return "VULNERABLE", f"uv audit found {count} known vulnerability/cies", []
    if code == 0:
        return "PASS", "Audit completed with no reported vulnerabilities", []
    return "WARN", output or "uv audit could not complete for this project", []


def scan_project(project: str, cache: Optional[Cache] = None) -> ProjectResult:
    """Scan a single uv project."""
    lock_status, lock_detail = _audit_lock(project)

    cache_hit = None
    lock_file = os.path.join(project, "uv.lock")
    if cache is not None and os.path.exists(lock_file):
        key = f"audit:{_lock_hash(lock_file)}"
        cached = cache.get(key)
        if cached is not None:
            try:
                data = json.loads(cached)
                cache_hit = data
            except json.JSONDecodeError:
                cache_hit = None

    if cache_hit is not None:
        audit_status = cache_hit["audit_status"]
        audit_detail = cache_hit["audit_detail"]
        vulns = [
            Vulnerability(**v) for v in cache_hit.get("vulnerabilities", [])
        ]
    else:
        audit_status, audit_detail, vulns = _audit_vulnerabilities(project)
        if cache is not None and os.path.exists(lock_file):
            key = f"audit:{_lock_hash(lock_file)}"
            cache.put(
                key,
                json.dumps(
                    {
                        "audit_status": audit_status,
                        "audit_detail": audit_detail,
                        "vulnerabilities": [asdict(v) for v in vulns],
                    }
                ),
            )

    return ProjectResult(
        path=project,
        lock_status=lock_status,
        lock_detail=lock_detail,
        audit_status=audit_status,
        audit_detail=audit_detail,
        vulnerabilities=vulns,
    )


def _find_python_exe(venv: str) -> Optional[str]:
    """Locate the python executable inside a venv (cross-platform)."""
    candidates = [
        os.path.join(venv, "Scripts", "python.exe"),
        os.path.join(venv, "bin", "python"),
        os.path.join(venv, "bin", "python.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def scan_venv(venv: str) -> VenvResult:
    """Inspect one virtual environment read-only."""
    py = _find_python_exe(venv)
    if py is None:
        return VenvResult(
            path=venv,
            python_version=None,
            pip_check_status="WARN",
            pip_check_detail="python executable not found in venv",
        )

    code, output = _run([py, "--version"], cwd=venv)
    if code != 0:
        return VenvResult(
            path=venv,
            python_version=None,
            pip_check_status="WARN",
            pip_check_detail=output or "python could not run",
        )
    python_version = output.strip()

    code, output = _run(["uv", "pip", "check", "--python", py], cwd=venv)
    if code == 0:
        detail = output.strip() or "Package dependencies consistent"
        return VenvResult(venv, python_version, "PASS", detail)
    return VenvResult(venv, python_version, "WARN", output or "inconsistent/broken package dependencies")


def discover_projects(root: str) -> List[str]:
    """Find directories containing a uv.lock file."""
    found: List[str] = []
    root_path = Path(root)
    for lock_file in root_path.rglob("uv.lock"):
        found.append(str(lock_file.parent))
    return sorted(set(found))


def discover_venvs(root: str) -> List[str]:
    """Find directories named .venv or venv."""
    found: List[str] = []
    root_path = Path(root)
    for entry in root_path.rglob("*"):
        if entry.is_dir() and entry.name in {".venv", "venv"}:
            found.append(str(entry))
    return sorted(set(found))


def scan_root(
    root: str,
    workers: int = 0,
    cache: Optional[Cache] = None,
) -> ScanResult:
    """Scan all uv projects and venvs under ``root``.

    Projects are audited in parallel using a thread pool sized to ``workers``
    (0 means use the number of CPU cores).
    """
    import time

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    projects = discover_projects(root)
    venvs = discover_venvs(root)

    if workers <= 0:
        import os as _os

        workers = max(1, min(8, (_os.cpu_count() or 2)))

    project_results: List[ProjectResult] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_project = {
            executor.submit(scan_project, p, cache): p for p in projects
        }
        for future in as_completed(future_to_project):
            project_results.append(future.result())

    # Sort for stable, scan-friendly output.
    project_results.sort(key=lambda p: p.path)

    venv_results = [scan_venv(v) for v in venvs]

    summary = ScanSummary(
        projects=len(project_results),
        venvs=len(venv_results),
        vulnerable_projects=sum(
            1 for p in project_results if p.audit_status == "VULNERABLE"
        ),
        total_vulnerabilities=sum(p.vuln_count for p in project_results),
        lock_problems=sum(1 for p in project_results if p.lock_status == "WARN"),
        env_problems=sum(1 for v in venv_results if v.pip_check_status == "WARN"),
    )

    return ScanResult(
        root=os.path.abspath(root),
        timestamp=timestamp,
        projects=project_results,
        venvs=venv_results,
        summary=summary,
    )
