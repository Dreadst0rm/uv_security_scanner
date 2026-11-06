"""Report generation: JSON and self-contained filterable HTML."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import List

from .models import ScanResult

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>uv Security Report — {root}</title>
<style>
  :root{--bg:#f6f8fa;--card:#ffffff;--text:#24292e;--muted:#57606a;
         --crit:#cf222e;--high:#d9480f;--med:#b08800;--low:#19773c;
         --pass:#19773c;--border:#d0d7de;}
  *{box-sizing:border-box;}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
       background:var(--bg);color:var(--text);margin:0;padding:24px;}
  .wrap{max-width:1200px;margin:0 auto;}
  header{margin-bottom:24px;}
  h1{font-size:24px;margin:0 0 4px 0;display:flex;align-items:center;gap:10px;}
  h1 .dot{width:10px;height:10px;border-radius:50%;background:var(--muted);}
  h1 .dot.crit{background:var(--crit);}
  .meta{color:var(--muted);font-size:14px;margin-bottom:16px;}
  .summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px;}
  .stat{background:var(--card);border:1px solid var(--border);border-radius:8px;
        padding:12px 16px;min-width:150px;}
  .stat .v{font-size:26px;font-weight:700;display:block;}
  .stat .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;}
  .stat .v.crit{color:var(--crit);}.stat .v.high{color:var(--high);}
  .stat .v.med{color:var(--med);}.stat .v.low{color:var(--low);}
  .stat .v.pass{color:var(--pass);}
  .toolbar{background:var(--card);border:1px solid var(--border);border-radius:8px;
           padding:12px 16px;margin-bottom:16px;display:flex;flex-wrap:wrap;gap:12px;align-items:center;}
  .toolbar label{font-size:13px;color:var(--muted);display:flex;align-items:center;gap:6px;}
  .toolbar select,.toolbar input{padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:#fff;font-size:14px;}
  .badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;
         text-transform:uppercase;letter-spacing:.02em;color:#fff;}
  .b-crit{background:var(--crit);}.b-high{background:var(--high);}.b-med{background:var(--med);}.b-low{background:var(--low);}.b-pass{background:var(--pass);}
  table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden;}
  th{background:#f3f5f7;color:var(--muted);font-size:12px;text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);user-select:none;}
  td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:14px;}
  tr:last-child td{border-bottom:none;}
  tr:hover{background:#f6f8fa;}
  .pkg{font-weight:600;color:#1f6feb;}
  .ver{color:var(--muted);font-size:13px;}
  .fixed{color:var(--low);font-size:13px;}
  .adv{font-size:12px;color:var(--muted);word-break:break-all;}
  .adv a{color:#1f6feb;text-decoration:none;}
  .adv a:hover{text-decoration:underline;}
  .actions{white-space:nowrap;}
  .btn{background:var(--card);border:1px solid var(--border);color:var(--text);
       padding:4px 10px;border-radius:6px;font-size:12px;cursor:pointer;}
  .btn:hover{border-color:#1f6feb;color:#1f6feb;}
  .fixbtn{background:#1f6feb;color:#fff;border-color:#1f6feb;}
  .fixbtn:hover{background:#1565c0;}
  .empty{color:var(--muted);padding:24px;text-align:center;}
  .venv-section{margin-top:32px;}
  h2{font-size:18px;margin:0 0 8px 0;color:var(--muted);border-bottom:1px solid var(--border);padding-bottom:6px;}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;background:#f3f5f7;
        padding:2px 6px;border-radius:4px;color:#d73a49;}
  .severity-rank{display:none;}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1><span class="dot {dot_class}"></span>uv Security Report</h1>
  <div class="meta">
    <strong>Root:</strong> {esc_root}&nbsp;|&nbsp;
    <strong>Generated:</strong> {esc_ts}&nbsp;|&nbsp;
    <strong>Projects:</strong> {n_projects}&nbsp;|&nbsp;
    <strong>Vulnerable projects:</strong> <span class="badge b-{crit_class}">{n_vuln_proj}</span>&nbsp;|&nbsp;
    <strong>Total vulnerabilities:</strong> {n_vuln}
  </div>
</header>

<div class="summary">
  <div class="stat"><span class="v pass">{n_projects}</span><span class="l">projects scanned</span></div>
  <div class="stat"><span class="v {vuln_stat_class}">{n_vuln_proj}</span><span class="l">vulnerable projects</span></div>
  <div class="stat"><span class="v {crit_stat_class}">{n_crit}</span><span class="l">critical</span></div>
  <div class="stat"><span class="v {high_stat_class}">{n_high}</span><span class="l">high</span></div>
  <div class="stat"><span class="v {med_stat_class}">{n_med}</span><span class="l">medium</span></div>
  <div class="stat"><span class="v {low_stat_class}">{n_low}</span><span class="l">low</span></div>
  <div class="stat"><span class="v pass">{n_lock}</span><span class="l">lock problems</span></div>
  <div class="stat"><span class="v pass">{n_env}</span><span class="l">env problems</span></div>
</div>

<div class="toolbar">
  <label>Severity
    <select id="sevFilter"><option value="">All</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option><option value="Unscored">Unscored</option></select>
  </label>
  <label>Project
    <select id="projFilter"><option value="">All projects</option>{proj_options}</select>
  </label>
  <label>Package <input id="pkgFilter" placeholder="filter by package..."></label>
  <span id="matchCount" style="font-size:13px;color:var(--muted);"></span>
</div>

<table id="findingsTable">
  <thead>
    <tr>
      <th style="width:6%;">Severity</th>
      <th style="width:22%;">Project</th>
      <th style="width:16%;">Package</th>
      <th style="width:12%;">Installed</th>
      <th style="width:12%;">Fixed in</th>
      <th style="width:22%;">Advisory / summary</th>
      <th style="width:10%;">Actions</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>

<div class="venv-section">
  <h2>Virtual Environments ({n_venvs})</h2>
  {venv_rows}
</div>

<script>
const sevFilter = document.getElementById('sevFilter');
const projFilter = document.getElementById('projFilter');
const pkgFilter = document.getElementById('pkgFilter');
const matchCount = document.getElementById('matchCount');
const rows = Array.from(document.querySelectorAll('#findingsTable tbody tr'));
function rank(sev){switch(sev){case'Critical':return 5;case'High':return 4;case'Medium':return 3;case'Low':return 2;case'Unscored':return 1;default:return 0;}}
function filter(){
  const s=sevFilter.value.toLowerCase(); const p=projFilter.value.toLowerCase(); const k=pkgFilter.value.toLowerCase();
  let shown=0;
  for(const tr of rows){
    const sev=tr.dataset.sev||'';
    const proj=tr.dataset.proj||'';
    const pkg=tr.dataset.pkg||'';
    const ok=(!s || sev.toLowerCase()===s) && (!p || proj.toLowerCase()===p) && (!k || pkg.toLowerCase().includes(k));
    tr.style.display=ok?'':'none';
    if(ok) shown++;
  }
  matchCount.textContent=shown+' of '+rows.length+' finding(s) shown';
}
sevFilter.onchange=filter; projFilter.onchange=filter; pkgFilter.oninput=filter;
filter();
</script>
</div>
</body>
</html>
"""

_SEVERITY_CLASS = {
    "Critical": "crit",
    "High": "high",
    "Medium": "med",
    "Low": "low",
    "Unscored": "med",
}


def _escape_template_braces(template: str) -> str:
    """Double ``{``/``}`` inside <style> and <script> blocks so str.format()
    does not interpret CSS/JS braces as placeholders. Format placeholders
    live outside those blocks and are left untouched."""
    import re

    def repl(m):
        tag = m.group(1)
        inner = m.group(2)
        inner = inner.replace("{", "{{").replace("}", "}}")
        return f"<{tag}>{inner}</{tag}>"

    return re.sub(r"<(style|script)>(.*?)</\1>", repl, template, flags=re.S)


# Escape CSS/JS braces once at import time; placeholders remain single-braced.
HTML_TEMPLATE = _escape_template_braces(HTML_TEMPLATE)


def _esc(s: str) -> str:
    return html.escape(s or "")


def _severity_of(vuln) -> str:
    sev = (vuln.severity or "Unscored").strip()
    # uv does not emit CVSS; approximate from advisory id family if unscored.
    if sev == "Unscored":
        aid = (vuln.advisory_id or "").upper()
        if aid.startswith("CVE"):
            sev = "High"
        elif aid.startswith("PYSEC"):
            sev = "Medium"
    return sev


def _class_of(sev: str) -> str:
    return _SEVERITY_CLASS.get(sev, "med")


def build_html(result: ScanResult) -> str:
    s = result.summary
    rows: List[str] = []
    n_crit = n_high = n_med = n_low = 0
    has_crit = False

    projects_seen = set()
    for p in result.projects:
        projects_seen.add(p.path)
        for v in p.vulnerabilities:
            sev = _severity_of(v)
            cls = _class_of(sev)
            if sev == "Critical":
                n_crit += 1; has_crit = True
            elif sev == "High":
                n_high += 1
            elif sev == "Medium":
                n_med += 1
            elif sev == "Low":
                n_low += 1
            fix_cmd = f'uv add "{v.package}=={v.fixed_version}"' if v.fixed_version else "n/a"
            rows.append(
                f"""<tr data-sev="{html.escape(sev)}" data-proj="{_esc(p.path)}" data-pkg="{_esc(v.package)}">
  <td><span class="badge b-{cls}">{sev}</span></td>
  <td><span class="mono">{_esc(p.path)}</span></td>
  <td><span class="pkg">{_esc(v.package)}</span><div class="ver">{_esc(v.advisory_id)}</div></td>
  <td><span class="ver">{_esc(v.installed_version)}</span></td>
  <td><span class="fixed">{_esc(v.fixed_version or "—")}</span></td>
  <td><div class="adv">{_esc(v.summary)}<div>{_esc(v.advisory_url or "")}</div></div></td>
  <td class="actions">
    <button class="btn fixbtn" data-fix="{_esc(fix_cmd)}" onclick="prompt('Upgrade command', this.getAttribute('data-fix'))">Fix</button>
  </td>
</tr>"""
            )

    if not rows:
        rows.append(
            '<tr><td colspan="7" class="empty">No vulnerabilities found. ✅</td></tr>'
        )

    proj_options = "".join(
        f'<option value="{_esc(p)}">{_esc(p)}</option>' for p in sorted(projects_seen)
    )

    # Vulnerability badge class for summary (worst severity present).
    crit_class = "crit" if n_crit else ("high" if n_high else ("med" if n_med else ("low" if n_low else "pass")))

    venv_rows: List[str] = []
    if result.venvs:
        for v in result.venvs:
            cls = _class_of("pass" if v.pip_check_status == "PASS" else "med")
            venv_rows.append(
                f"""<tr>
  <td><span class="badge b-{cls}">{v.pip_check_status}</span></td>
  <td><span class="mono">{_esc(v.path)}</span></td>
  <td>{_esc(v.python_version or "—")}</td>
  <td><div class="adv">{_esc(v.pip_check_detail)}</div></td>
</tr>"""
            )
    else:
        venv_rows.append('<tr><td colspan="7" class="empty">No virtual environments found.</td></tr>')

    # Build a venv table header
    venv_table = (
        '<table><thead><tr>'
        '<th style="width:10%;">Status</th>'
        '<th style="width:30%;">Path</th>'
        '<th style="width:15%;">Python</th>'
        '<th>pip check detail</th>'
        '</tr></thead><tbody>'
        + "".join(venv_rows)
        + "</tbody></table>"
    )

    # Pre-compute severity-based CSS classes (str.format cannot evaluate
    # inline expressions, so they must be resolved here).
    def _stat_class(count, good="pass", bad="high"):
        return bad if count > 0 else good

    dot_class = "crit" if has_crit else ""
    ctx = {
        "root": _esc(result.root),
        "esc_root": _esc(result.root),
        "esc_ts": _esc(result.timestamp),
        "n_projects": s.projects,
        "n_vuln_proj": s.vulnerable_projects,
        "n_vuln": s.total_vulnerabilities,
        "n_crit": n_crit,
        "n_high": n_high,
        "n_med": n_med,
        "n_low": n_low,
        "n_lock": s.lock_problems,
        "n_env": s.env_problems,
        "n_venvs": len(result.venvs),
        "dot_class": dot_class,
        "vuln_stat_class": _stat_class(s.vulnerable_projects),
        "crit_class": crit_class,
        "crit_stat_class": _stat_class(n_crit),
        "high_stat_class": _stat_class(n_high),
        "med_stat_class": _stat_class(n_med),
        "low_stat_class": _stat_class(n_low),
        "proj_options": proj_options,
        "rows": "\n".join(rows),
        "venv_rows": venv_table,
    }
    return HTML_TEMPLATE.format(**ctx)


def write_html_report(result: ScanResult, path: str) -> str:
    content = build_html(result)
    p = Path(path)
    p.write_text(content, encoding="utf-8")
    return str(p.resolve())


def write_json_report(result: ScanResult, path: str) -> str:
    payload = result.to_dict()
    p = Path(path)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(p.resolve())
