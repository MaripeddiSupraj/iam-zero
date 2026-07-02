import fnmatch
import json


def _action_matches(pattern: str, action: str) -> bool:
    """True if an IAM action pattern (may contain wildcards) covers `action`."""
    if pattern == action:
        return True
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatchcase(action.lower(), pattern.lower())
    return False


def generate_minimal_policy(
    used_actions: set[str],
    findings: list[dict],
    original_docs: list[dict],
) -> str:
    """
    Builds a minimal IAM policy JSON keeping only:
    - Actions confirmed as used (even if only covered by a wildcard in the
      original policy — they are expanded to explicit action names)
    - Actions Claude marked as 'keep' or 'investigate'
    """
    keep_actions: set[str] = set(used_actions)
    for f in findings:
        rec = f.get("recommendation", "investigate").lower()
        if rec in ("keep", "investigate"):
            keep_actions.add(f["permission"])

    # Map each kept action to the resources of every original statement
    # that covers it — exact match OR wildcard match. This is what makes
    # 's3:GetObject' survive when the original policy only said 's3:*'.
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
            for kept in keep_actions:
                if any(_action_matches(p, kept) for p in stmt_actions):
                    resource_map.setdefault(kept, set()).update(resources)

    # Any kept action not covered by the original policy at all (shouldn't
    # normally happen) is preserved with Resource "*" and flagged via Sid
    # rather than silently dropped.
    orphans = sorted(a for a in keep_actions if a not in resource_map)

    # Group by resource sets to keep the policy compact
    resource_to_actions: dict[str, list[str]] = {}
    for action, resources in resource_map.items():
        key = json.dumps(sorted(resources))
        resource_to_actions.setdefault(key, []).append(action)

    statements = []
    for resources_json, actions in sorted(resource_to_actions.items()):
        statements.append(
            {
                "Effect": "Allow",
                "Action": sorted(actions),
                "Resource": json.loads(resources_json),
            }
        )
    if orphans:
        statements.append(
            {
                "Sid": "IamZeroReviewUnmappedActions",
                "Effect": "Allow",
                "Action": orphans,
                "Resource": "*",
            }
        )

    policy = {"Version": "2012-10-17", "Statement": statements}
    return json.dumps(policy, indent=2)
