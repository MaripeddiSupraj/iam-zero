import json


def generate_minimal_bindings(
    service_account: str,
    current_roles: list[str],
    findings: list[dict],
) -> str:
    """
    Returns a JSON string representing the recommended IAM bindings,
    removing roles Claude marked as safe to remove.
    """
    remove_roles = {
        f["permission"]
        for f in findings
        if f.get("recommendation", "investigate").lower() == "remove"
    }

    kept_roles = [r for r in current_roles if r not in remove_roles]

    result = {
        "serviceAccount": service_account,
        "recommendedRoles": kept_roles,
        "removedRoles": sorted(remove_roles),
        "note": (
            "Apply by removing the listed roles from the service account's "
            "project-level IAM bindings."
        ),
    }
    return json.dumps(result, indent=2)
