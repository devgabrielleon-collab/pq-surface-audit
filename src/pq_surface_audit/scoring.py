from __future__ import annotations

from pq_surface_audit.models import AssetResult, Finding


HIGH = {"high": 25, "medium": 10, "low": 4, "info": 0}


def _score_delta(finding: Finding) -> int:
    return HIGH.get(finding.severity, 0)


def score_asset(asset: AssetResult) -> AssetResult:
    score = 100
    for finding in asset.findings:
        score -= _score_delta(finding)

    # Slight uplift in urgency if multiple exposed services are present.
    exposed = sum(1 for o in asset.observations if o.status == "open")
    if exposed >= 2:
        score -= 5
        asset.notes.append("Multiple internet-facing services observed.")

    score = max(0, score)
    asset.score = score

    if score <= 55:
        asset.priority = "high"
    elif score <= 80:
        asset.priority = "medium"
    else:
        asset.priority = "low"

    return asset
