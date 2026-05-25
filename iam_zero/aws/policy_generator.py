import json


def generate_minimal_policy(
    used_actions: set[str],
    findings: list[dict],
    original_docs: list[dict],
) -> str:
    """
    Builds a minimal IAM policy JSON keeping only:
    - Actions confirmed as used
    - Actions Claude marked as 'keep' or 'investigate'
    """
    keep_actions: set[str] = set(used_actions)
    for f in findings:
        rec = f.get("recommendation", "investigate").lower()
        if rec in ("keep", "investigate"):
            keep_actions.add(f["permission"])

    # Gather resources from the original policy statements for kept actions
    resource_map: dict[str, set[str]] = {}
    for doc in original_docs:
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            stmt_actions = stmt.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]
            resources = stmt.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]
            for a in stmt_actions:
                if a in keep_actions:
                    resource_map.setdefault(a, set()).update(resources)

    if not resource_map:
        # Nothing to keep → empty policy
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        return json.dumps(policy, indent=2)

    # Group by resource sets to keep the policy compact
    resource_to_actions: dict[str, list[str]] = {}
    for action, resources in resource_map.items():
        key = json.dumps(sorted(resources))
        resource_to_actions.setdefault(key, []).append(action)

    statements = []
    for resources_json, actions in resource_to_actions.items():
        statements.append(
            {
                "Effect": "Allow",
                "Action": sorted(actions),
                "Resource": json.loads(resources_json),
            }
        )

    policy = {"Version": "2012-10-17", "Statement": statements}
    return json.dumps(policy, indent=2)
