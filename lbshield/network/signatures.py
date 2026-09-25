"""Network attack signature helpers."""

from __future__ import annotations

from lbshield.models import AttackSignature


def deduplicate_signatures(signatures: list[AttackSignature]) -> list[AttackSignature]:
    by_key: dict[tuple[str, str, str | None], AttackSignature] = {}
    for signature in signatures:
        key = (signature.name, signature.layer, signature.target)
        existing = by_key.get(key)
        if not existing:
            by_key[key] = signature
            continue
        existing.last_seen = max(existing.last_seen, signature.last_seen)
        existing.peak_pps = max(existing.peak_pps or 0, signature.peak_pps or 0) or None
        existing.peak_bps = max(existing.peak_bps or 0, signature.peak_bps or 0) or None
        existing.evidence.extend(item for item in signature.evidence if item not in existing.evidence)
    return list(by_key.values())

