"""File integrity monitoring."""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: str) -> str | None:
    target = Path(path)
    if not target.exists() or not target.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with target.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except (PermissionError, OSError):
        return None
    return digest.hexdigest()


def collect_hashes(paths: list[str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in paths:
        digest = sha256_file(path)
        if digest:
            hashes[path] = digest
    return hashes

