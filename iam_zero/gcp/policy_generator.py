import json


def generate_minimal_bindings(
    service_account: str,
    current_roles: list[str],
    findings: list[dict],
    *,
    allow_removals: bool = False,
) -> str:
    """Return a review-safe GCP IAM recommendation.

    Cloud Audit Log method names do not map 1:1 to IAM permissions and Data
    Access logs may be disabled. Therefore the current GCP analyzer is
    advisory-only: no role is removed unless a future provider-native evidence
    path explicitly opts in with allow_removals=True.
    """
    requested_removals = {
        f["permission"]
        for f in findings
        if f.get("recommendation", "investigate").lower() == "remove"
    }

    remove_roles = requested_removals if allow_removals else set()
    kept_roles = [role for role in current_roles if role not in remove_roles]

    result = {
        "schemaVersion": 1,
        "serviceAccount": service_account,
        "mode": "authoritative" if allow_removals else "advisory",
        "recommendedRoles": kept_roles,
        "removedRoles": sorted(remove_roles),
        "requestedRemovals": sorted(requested_removals),
        "note": (
            "No roles are removed automatically from audit-log heuristics. "
            "Use Google Cloud IAM Recommender / Policy Intelligence evidence "
            "and human review before applying a role reduction."
            if not allow_removals
            else
            "Removal mode was explicitly enabled by an authoritative evidence path."
        ),
    }
    return json.dumps(result, indent=2)
