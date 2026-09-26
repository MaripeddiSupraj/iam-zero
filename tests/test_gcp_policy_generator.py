import json

from iam_zero.gcp.policy_generator import generate_minimal_bindings


def test_default_mode_never_removes_role_from_heuristic_finding():
    sa = "test@project.iam.gserviceaccount.com"
    current = ["roles/storage.objectAdmin", "roles/compute.viewer"]
    findings = [
        {
            "permission": "roles/compute.viewer",
            "recommendation": "remove",
            "risk": "low",
        },
    ]

    result = json.loads(generate_minimal_bindings(sa, current, findings))

    assert result["mode"] == "advisory"
    assert result["recommendedRoles"] == current
    assert result["removedRoles"] == []
    assert result["requestedRemovals"] == ["roles/compute.viewer"]


def test_authoritative_mode_can_remove_explicit_role():
    sa = "test@project.iam.gserviceaccount.com"
    current = ["roles/storage.objectAdmin", "roles/compute.viewer"]
    findings = [
        {
            "permission": "roles/compute.viewer",
            "recommendation": "remove",
            "risk": "low",
        },
    ]

    result = json.loads(
        generate_minimal_bindings(
            sa,
            current,
            findings,
            allow_removals=True,
        )
    )

    assert result["mode"] == "authoritative"
    assert result["recommendedRoles"] == ["roles/storage.objectAdmin"]
    assert result["removedRoles"] == ["roles/compute.viewer"]


def test_investigate_roles_are_always_kept():
    sa = "test@project.iam.gserviceaccount.com"
    current = ["roles/iam.serviceAccountTokenCreator"]
    findings = [
        {
            "permission": "roles/iam.serviceAccountTokenCreator",
            "recommendation": "investigate",
            "risk": "high",
        },
    ]

    result = json.loads(
        generate_minimal_bindings(
            sa,
            current,
            findings,
            allow_removals=True,
        )
    )

    assert result["recommendedRoles"] == current
    assert result["removedRoles"] == []
