# uv-security

Fast, scan-friendly security scanner for [uv](https://github.com/astral-sh/uv)
projects. Discovers every `uv.lock` project under a root, audits them in
parallel, and lets you selectively upgrade vulnerable packages — with
colorized console output, JSON, and a filterable HTML report.

## Install

```bash
pip install uv-security
# or from this repo
pip install .
```

## Quick start

```bash
# Scan the current directory
uv-security scan

# Scan a specific root, emit JSON
uv-security scan /path/to/repos --json

# Parallel scan with caching, HTML + JSON reports
uv-security scan --workers 4 --report report.html

# Selectively upgrade a vulnerable package (preview first)
uv-security upgrade requests --project ./myapp --dry-run
uv-security upgrade requests --project ./myapp

# Regenerate reports from a saved JSON scan
uv-security report scan-20260101.json
```

## What it checks

- **Lock-file drift:** `uv lock --check` on every discovered `uv.lock`.
- **Vulnerabilities:** `uv --preview audit` per project, parsed per-package
  (package, installed version, fixed version, advisory ID, summary, URL).
- **Virtual environments:** inspects `.venv` / `venv` read-only and runs
  `uv pip check --python <interpreter>`.

## Features

### Easy to use
1. **Interactive selective upgrade** — `uv-security upgrade` lists packages
   with known fixes; pick one by number or name. `--dry-run` previews the
   exact `uv add` command before applying.
2. **Filterable HTML report** — one self-contained HTML file with a sortable
   table filterable by severity, project, and package. Each row has a "Fix"
   button that copies the upgrade command.
3. **Zero-config defaults** — `uv-security scan` with no args scans the
   current directory and writes a timestamped HTML + JSON report.

### Performance
1. **Parallel auditing** — all `uv audit` / `pip check` calls run in a thread
   pool sized to your CPU count.
2. **Result caching** — audit results are cached per `uv.lock` content hash
   under `.uv-security-cache/`; unchanged projects are skipped on re-runs.
3. **Streaming + early exit** — findings print as each project finishes; the
   process returns non-zero when issues exist (CI-friendly).

## Output format

`uv audit --preview` output is parsed into structured findings, e.g.:

```
[VULNERABLE] ./myapp (2)
  - requests 2.28.0 -> 2.33.0 | PYSEC-2026-2275 | Requests has Insecure Temp File Reuse ...
  - urllib3 1.26.20 -> 2.8.0 | PYSEC-2026-4177 | urllib3: HTTPResponse.stream() ...
```

Exit codes: `0` clean, `1` issues found, `3` uv not available.
