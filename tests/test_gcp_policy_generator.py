import json
import pytest
from iam_zero.gcp.policy_generator import generate_minimal_bindings


def test_removes_flagged_roles():
    sa = "test@project.iam.gserviceaccount.com"
    current = ["roles/storage.objectAdmin", "roles/compute.viewer", "roles/bigquery.dataViewer"]
    findings = [
        {"permission": "roles/compute.viewer", "recommendation": "remove", "risk": "low", "reason": "unused"},
    ]
    result = json.loads(generate_minimal_bindings(sa, current, findings))
    assert "roles/storage.objectAdmin" in result["recommendedRoles"]
    assert "roles/bigquery.dataViewer" in result["recommendedRoles"]
    assert "roles/compute.viewer" not in result["recommendedRoles"]
    assert "roles/compute.viewer" in result["removedRoles"]


def test_keeps_investigate_roles():
    sa = "test@project.iam.gserviceaccount.com"
    current = ["roles/iam.serviceAccountTokenCreator"]
    findings = [
        {"permission": "roles/iam.serviceAccountTokenCreator", "recommendation": "investigate", "risk": "high"},
    ]
    result = json.loads(generate_minimal_bindings(sa, current, findings))
    assert "roles/iam.serviceAccountTokenCreator" in result["recommendedRoles"]
