import copy
import fnmatch
import json


def _action_matches(pattern: str, action: str) -> bool:
    """True if an IAM action pattern (which may contain wildcards) covers action."""
    if pattern == action:
        return True
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatchcase(action.lower(), pattern.lower())
    return False


def _observed_through(pattern: str, used_actions: set[str]) -> bool:
    """Return True when an observed action is granted by pattern."""
    return any(_action_matches(pattern, used) for used in used_actions)


def generate_minimal_policy(
    used_actions: set[str],
    findings: list[dict],
    original_docs: list[dict],
) -> str:
    """Generate a conservative recommendation without broadening policy semantics.

    The generator edits original statements instead of rebuilding them from
    Action + Resource. This preserves Condition, Sid, NotResource, Principal,
    and explicit Deny statements.

    Only an explicit action marked remove is deleted. Missing/unknown findings
    are fail-closed and remain unchanged.

    Wildcard grants are not narrowed automatically when an observed action is
    covered by that wildcard. Historical activity is not sufficient proof that
    every unobserved action in the wildcard is safe to remove.
    """
    remove_actions = {
        str(f.get("permission", ""))
        for f in findings
        if str(f.get("recommendation", "investigate")).lower() == "remove"
    }
    remove_actions.discard("")

    statements: list[dict] = []

    for doc in original_docs:
        for original in doc.get("Statement", []):
            stmt = copy.deepcopy(original)

            # Deny and NotAction are security boundaries, not rewrite targets.
            if stmt.get("Effect") != "Allow" or "Action" not in stmt or "NotAction" in stmt:
                statements.append(stmt)
                continue

            raw_actions = stmt.get("Action", [])
            was_string = isinstance(raw_actions, str)
            actions = [raw_actions] if was_string else list(raw_actions)

            kept: list[str] = []
            for action in actions:
                if action not in remove_actions:
                    kept.append(action)
                    continue

                if action in used_actions:
                    kept.append(action)
                    continue

                if ("*" in action or "?" in action) and _observed_through(action, used_actions):
                    kept.append(action)
                    continue

                # This exact grant was explicitly marked safe to remove.

            if not kept:
                continue

            if was_string and len(kept) == 1:
                stmt["Action"] = kept[0]
            else:
                stmt["Action"] = kept
            statements.append(stmt)

    policy = {"Version": "2012-10-17", "Statement": statements}
    return json.dumps(policy, indent=2)
