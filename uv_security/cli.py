"""Command-line interface for uv-security."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .scanner import scan_root, discover_projects, discover_venvs
from .cache import Cache
from .report import write_html_report, write_json_report
from .upgrade import preview_upgrade, upgrade_package, list_upgradeable
from .models import Vulnerability


def _print_color(text: str, color: str, json_mode: bool) -> None:
    if json_mode:
        return
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "gray": "\033[90m",
        "reset": "\033[0m",
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")


def _format_summary(result) -> str:
    s = result.summary
    return (
        f"Projects: {s.projects} | Venvs: {s.venvs}\n"
        f"Vulnerable projects: {s.vulnerable_projects} | Total vulnerabilities: {s.total_vulnerabilities}\n"
        f"Lock problems: {s.lock_problems} | Env problems: {s.env_problems}"
    )


def cmd_scan(args) -> int:
    root = args.root or "."
    json_mode = bool(args.json)

    if not json_mode:
        _print_color(f"uv-security scan | Root: {root}", "cyan", False)

    cache = Cache(root, enabled=not args.no_cache)
    result = scan_root(root, workers=args.workers, cache=cache)

    if args.json:
        import json as _json
        print(_json.dumps(result.to_dict(), indent=2))
    else:
        _print_color("\n=== SUMMARY ===", "cyan", False)
        _print_color(_format_summary(result), "white", False)

        # Print per-project findings, highlighting vulnerabilities.
        for p in result.projects:
            if p.audit_status == "VULNERABLE":
                _print_color(f"\n[VULNERABLE] {p.path} ({p.vuln_count})", "red", False)
                for v in p.vulnerabilities:
                    fixed = f" -> {v.fixed_version}" if v.fixed_version else ""
                    print(
                        f"  - {v.package} {v.installed_version}{fixed} | {v.advisory_id} | {v.summary}"
                    )
            elif p.audit_status == "WARN":
                _print_color(f"\n[WARN] {p.path} | {p.lock_detail} / {p.audit_detail}", "yellow", False)
            else:
                _print_color(f"\n[PASS] {p.path}", "green", False)

        for v in result.venvs:
            if v.pip_check_status == "WARN":
                _print_color(f"\n[WARN] venv {v.path} | {v.pip_check_detail}", "yellow", False)
            else:
                _print_color(f"\n[PASS] venv {v.path} ({v.python_version})", "green", False)

        # Write reports.
        report_path = args.report or (
            f"uv-security-report-{result.timestamp.replace(':','-')}.html"
        )
        saved_html = write_html_report(result, report_path)
        json_path = report_path.rsplit(".", 1)[0] + ".json"
        saved_json = write_json_report(result, json_path)
        _print_color(f"\nHTML report: {saved_html}", "cyan", False)
        _print_color(f"JSON report: {saved_json}", "gray", False)

    return 1 if result.summary.has_issues else 0


def cmd_upgrade(args) -> int:
    project = args.project or "."
    packages = args.package
    dry_run = bool(args.dry_run)

    # Discover vulnerabilities in the project to offer default selection.
    from .scanner import scan_project
    from .cache import Cache

    cache = Cache(project, enabled=not args.no_cache)
    result = scan_project(project, cache=cache)

    if not packages:
        upgradeable = list_upgradeable(result.vulnerabilities)
        if not upgradeable:
            print("No packages with a known fixed version to upgrade.")
            return 0
        print("Packages with known fixes:")
        for i, name in enumerate(upgradeable, 1):
            print(f"  {i}) {name}")
        choice = input("\nSelect package number to upgrade (or name): ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(upgradeable):
                packages = [upgradeable[idx]]
            else:
                print("Invalid selection.")
                return 1
        else:
            packages = [choice]

    exit_code = 0
    for name in packages:
        # Find the fixed version from findings if possible.
        fixed = None
        for v in result.vulnerabilities:
            if v.package == name and v.fixed_version:
                fixed = v.fixed_version
                break
        if not fixed:
            ok, msg, latest = preview_upgrade(name)
            if not ok:
                print(msg)
                exit_code = 1
                continue
            fixed = latest

        ok, msg = upgrade_package(project, name, fixed, dry_run=dry_run)
        print(msg)
        if not ok:
            exit_code = 1
    return exit_code


def cmd_report(args) -> int:
    """Regenerate reports from an existing JSON scan result."""
    import json as _json
    from .models import ScanResult

    with open(args.file, "r", encoding="utf-8") as f:
        data = _json.load(f)
    # Reconstruct minimally for reporting.
    result = ScanResult(
        root=data.get("root", "."),
        timestamp=data.get("timestamp", ""),
        projects=[],
        venvs=[],
    )
    # We only need summary-level; projects re-hydrated lightly.
    from .models import ProjectResult, Vulnerability

    for pd in data.get("projects", []):
        vulns = [Vulnerability(**v) for v in pd.get("vulnerabilities", [])]
        result.projects.append(
            ProjectResult(
                path=pd["path"],
                lock_status=pd.get("lock_status", ""),
                lock_detail=pd.get("lock_detail", ""),
                audit_status=pd.get("audit_status", ""),
                audit_detail=pd.get("audit_detail", ""),
                vulnerabilities=vulns,
            )
        )
    for vd in data.get("venvs", []):
        from .models import VenvResult

        result.venvs.append(
            VenvResult(
                path=vd["path"],
                python_version=vd.get("python_version"),
                pip_check_status=vd.get("pip_check_status", ""),
                pip_check_detail=vd.get("pip_check_detail", ""),
            )
        )
    result.summary.projects = len(result.projects)
    result.summary.venvs = len(result.venvs)
    result.summary.vulnerable_projects = sum(
        1 for p in result.projects if p.audit_status == "VULNERABLE"
    )
    result.summary.total_vulnerabilities = sum(p.vuln_count for p in result.projects)
    result.summary.lock_problems = data["summary"].get("lock_problems", 0)
    result.summary.env_problems = data["summary"].get("env_problems", 0)

    import os

    html_path = args.out or data["root"].replace(os.sep, "_") + "-report.html"
    html_path = write_html_report(result, html_path)
    json_path = html_path.rsplit(".", 1)[0] + ".json"
    write_json_report(result, json_path)
    print(f"HTML report: {html_path}")
    print(f"JSON report: {json_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uv-security",
        description="Scan-friendly security scanner for uv projects with selective upgrades.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan uv projects and venvs for vulnerabilities.")
    p_scan.add_argument("root", nargs="?", default=".", help="Root directory to scan (default: cwd).")
    p_scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON to stdout.")
    p_scan.add_argument("--report", help="Write HTML report to this path (default: timestamped html).")
    p_scan.add_argument("--workers", type=int, default=0, help="Parallel audit workers (0 = auto).")
    p_scan.add_argument("--no-cache", action="store_true", help="Disable result caching.")
    p_scan.set_defaults(func=cmd_scan)

    p_upg = sub.add_parser("upgrade", help="Selectively upgrade a vulnerable package.")
    p_upg.add_argument("package", nargs="*", help="Package name(s) to upgrade (interactive if omitted).")
    p_upg.add_argument("--project", default=".", help="Project directory (default: cwd).")
    p_upg.add_argument("--dry-run", action="store_true", help="Preview the upgrade command without applying.")
    p_upg.add_argument("--no-cache", action="store_true", help="Disable result caching.")
    p_upg.set_defaults(func=cmd_upgrade)

    p_rep = sub.add_parser("report", help="Regenerate HTML/JSON reports from a saved JSON scan.")
    p_rep.add_argument("file", help="Path to a previously saved JSON scan result.")
    p_rep.add_argument("--out", help="Output HTML path.")
    p_rep.set_defaults(func=cmd_report)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except BrokenPipeError:  # pragma: no cover
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
