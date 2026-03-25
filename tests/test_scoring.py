from pq_surface_audit.models import AssetResult, Finding, ServiceObservation
from pq_surface_audit.scoring import score_asset


def test_score_asset_priority_changes():
    asset = AssetResult(target="example.com", hostname="example.com", port=443)
    asset.observations.append(ServiceObservation(service="https", status="open", details={}))
    asset.observations.append(ServiceObservation(service="ssh", status="open", details={}))
    asset.findings.append(Finding(severity="high", category="tls", title="legacy", description=""))
    asset.findings.append(Finding(severity="medium", category="pq-readiness", title="classical cert", description=""))
    scored = score_asset(asset)
    assert scored.score == 60
    assert scored.priority == "medium"
    assert scored.notes
