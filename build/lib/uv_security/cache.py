"""Simple disk cache for audit results, keyed by uv.lock content hash."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


class Cache:
    """Persistent JSON cache stored under ``<root>/.uv-security-cache``."""

    def __init__(self, root: str, enabled: bool = True):
        self.enabled = enabled
        self.dir: Optional[Path] = None
        if enabled:
            self.dir = Path(root) / ".uv-security-cache"
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.dir = None
                self.enabled = False

    def _path(self, key: str) -> Path:
        assert self.dir is not None
        # Use first two chars as a subdirectory to avoid too many files in one dir.
        sub = self.dir / key[:2]
        sub.mkdir(parents=True, exist_ok=True)
        return sub / key

    def get(self, key: str) -> Optional[str]:
        if not self.enabled or self.dir is None:
            return None
        p = self._path(key)
        if not p.exists():
            return None
        try:
            return p.read_text(encoding="utf-8")
        except OSError:
            return None

    def put(self, key: str, value: str) -> None:
        if not self.enabled or self.dir is None:
            return
        try:
            self._path(key).write_text(value, encoding="utf-8")
        except OSError:
            pass
