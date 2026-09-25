"""Apache access log parser."""

from __future__ import annotations

from lbshield.parsers.nginx import parse_nginx_access


def parse_apache_access(line: str) -> dict[str, object] | None:
    return parse_nginx_access(line)

