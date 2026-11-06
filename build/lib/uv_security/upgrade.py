"""Selective package upgrade helpers."""

from __future__ import annotations

from typing import List, Optional, Tuple

from .scanner import _run


def preview_upgrade(
    package: str, version: Optional[str] = None
) -> Tuple[bool, str, Optional[str]]:
    """Show what upgrading ``package`` would do, without applying it.

    The fixed version comes from the ``uv audit`` finding (passed in as
    ``version``), so no extra network lookup is needed.
    """
    target = version or "latest"
    cmd = f'uv add "{package}=={target}"' if version else f'uv add "{package}"'
    msg = f"{package}: would upgrade to {target}\nRun: {cmd}"
    return True, msg, version


def list_upgradeable(vulnerabilities) -> List[str]:
    """Return sorted package names that have a known fixed version."""
    names = set()
    for v in vulnerabilities:
        if v.fixed_version:
            names.add(v.package)
    return sorted(names)


def upgrade_package(
    project: str,
    package: str,
    version: str,
    dry_run: bool = False,
) -> Tuple[bool, str]:
    """Upgrade ``package`` to ``version`` in ``project`` using ``uv add``.

    Returns (success, message).
    """
    if dry_run:
        cmd = f'uv add "{package}"' if version is None else f'uv add "{package}=={version}"'
        return True, f"[dry-run] would run: {cmd}"

    cmd = ["uv", "add", package] if version is None else ["uv", "add", f"{package}=={version}"]
    code, output = _run(cmd, cwd=project)
    target = version or "latest"
    if code == 0:
        return True, f"Upgraded {package} to {target} in {project}"
    return False, output or f"failed to upgrade {package}"
