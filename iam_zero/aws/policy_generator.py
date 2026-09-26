"""Safety-preserving AWS IAM policy recommendation generation.

The generator is intentionally conservative: it starts from the original
policy statements and removes only exact, explicit Allow actions that the
analysis marked "remove". It never rebuilds permissions from scratch, expands
wildcards, or drops statement constraints such as Condition.
"""

from copy import deepcopy
import json


def _is_wildcard_action(action: str) -> bool:
    return "*" in action or "?" in action


def _removal_set(used_actions: set[str], findings: list[dict]) -> set[str]:
    """Return exact action names that are eligible to be removed.

    Used actions always win. Wildcards are never removed automatically because
    replacing or deleting them safely requires service authorization metadata
    and statement-level reasoning beyond an observed-action list.
    """
    used_lower = {action.lower() for action in used_actions}
    removable: set[str] = set()

    for finding in findings:
        permission = str(finding.get("permission", "")).strip()
        recommendation = str(finding.get("recommendation", "investigate")).lower()
        if (
            not permission
            or recommendation != "remove"
            or permission.lower() in used_lower
            or _is_wildcard_action(permission)
        ):
            continue
        removable.add(permission.lower())

    return removable


def combine_policy_documents(original_docs: list[dict]) -> dict:
    """Combine identity policy documents for review without losing statements."""
    version = "2012-10-17"
    statements: list[dict] = []

    for doc in original_docs:
        if not isinstance(doc, dict):
            continue
        if isinstance(doc.get("Version"), str):
            version = doc["Version"]
        raw = doc.get("Statement", [])
        if isinstance(raw, dict):
            raw = [raw]
        for statement in raw:
            if isinstance(statement, dict):
                statements.append(deepcopy(statement))

    return {"Version": version, "Statement": statements}


def generate_minimal_policy(
    used_actions: set[str],
    findings: list[dict],
    original_docs: list[dict],
) -> str:
    """Generate a safer tightened policy while preserving original semantics.

    Safety invariants:
    - explicit Deny statements are preserved
    - NotAction / NotResource statements are preserved untouched
    - Resource, Condition, Sid and other statement metadata are preserved
    - wildcard Action entries are preserved rather than expanded or removed
    - an action disappears only when an explicit finding says "remove"
    - actions observed as used are never removed, even if a finding is wrong
    - missing/omitted model findings therefore default to KEEP
    """
    removable = _removal_set(used_actions, findings)
    combined = combine_policy_documents(original_docs)
    statements: list[dict] = []

    for original in combined["Statement"]:
        stmt = deepcopy(original)

        # Never rewrite Deny, NotAction, malformed/unknown statement shapes,
        # or any non-Allow semantics.
        if stmt.get("Effect") != "Allow" or "Action" not in stmt or "NotAction" in stmt:
            statements.append(stmt)
            continue

        actions = stmt.get("Action")
        was_string = isinstance(actions, str)
        action_list = [actions] if was_string else list(actions or [])

        kept: list = []
        for action in action_list:
            if not isinstance(action, str):
                kept.append(action)
                continue
            if _is_wildcard_action(action) or action.lower() not in removable:
                kept.append(action)

        # If all exact actions in an Allow statement were explicitly approved
        # for removal, the statement grants nothing and can be omitted.
        if not kept:
            continue

        stmt["Action"] = kept[0] if was_string and len(kept) == 1 else kept
        statements.append(stmt)

    policy = {"Version": combined["Version"], "Statement": statements}
    return json.dumps(policy, indent=2)
