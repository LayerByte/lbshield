"""Web server log monitoring."""

from __future__ import annotations

from pathlib import Path

from lbshield.parsers.apache import parse_apache_access
from lbshield.parsers.nginx import parse_nginx_access


def scan_access_logs(paths: list[str], max_lines: int = 1000) -> dict[str, object]:
    requests = 0
    errors = 0
    paths_seen: dict[str, int] = {}
    sources: set[str] = set()
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max_lines:]
        except (PermissionError, OSError):
            continue
        for line in lines:
            parsed = parse_nginx_access(line) or parse_apache_access(line)
            if not parsed:
                continue
            requests += 1
            sources.add(parsed["source"])
            request_path = parsed["path"]
            paths_seen[request_path] = paths_seen.get(request_path, 0) + 1
            if int(parsed["status"]) >= 400:
                errors += 1
    top_path = max(paths_seen.items(), key=lambda item: item[1], default=(None, 0))
    return {"requests": requests, "errors": errors, "unique_sources": len(sources), "top_path": top_path[0], "top_path_count": top_path[1]}

