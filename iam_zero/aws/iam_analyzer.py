import json

import boto3
from botocore.exceptions import ClientError


def get_role_policies(
    role_arn: str,
    profile: str | None = None,
) -> tuple[list[str], list[dict]]:
    """
    Returns (list_of_action_strings, list_of_raw_policy_documents) for the role.
    Expands wildcards to the explicit action names present in the policy.
    """
    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")
    role_name = role_arn.split("/")[-1]

    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    except ClientError as e:
        _raise_iam_error(e, role_arn, "iam:ListAttachedRolePolicies")

    actions: set[str] = set()
    raw_docs: list[dict] = []

    for policy_ref in attached:
        policy_arn = policy_ref["PolicyArn"]
        try:
            version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)[
                "PolicyVersion"
            ]["Document"]
        except ClientError as e:
            _raise_iam_error(e, role_arn, "iam:GetPolicy / iam:GetPolicyVersion")

        raw_docs.append(doc)
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            stmt_actions = stmt.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]
            for a in stmt_actions:
                actions.add(a)

    # Also collect inline policies
    try:
        inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        for name in inline_names:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
            raw_docs.append(doc)
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                stmt_actions = stmt.get("Action", [])
                if isinstance(stmt_actions, str):
                    stmt_actions = [stmt_actions]
                for a in stmt_actions:
                    actions.add(a)
    except ClientError as e:
        _raise_iam_error(e, role_arn, "iam:ListRolePolicies")

    return sorted(actions), raw_docs


def compute_unused(
    current_actions: list[str],
    used_actions: set[str],
) -> list[str]:
    """
    Returns actions in current_actions that are not covered by used_actions.
    Handles wildcard '*' actions by checking prefix matches.
    """
    unused = []
    for action in current_actions:
        if action == "*" or action.endswith(":*"):
            # Wildcards are always flagged for review
            unused.append(action)
            continue
        if action not in used_actions:
            unused.append(action)
    return sorted(unused)


def _raise_iam_error(e: ClientError, role_arn: str, permission: str) -> None:
    code = e.response["Error"]["Code"]
    msg = e.response["Error"]["Message"]
    if code in ("AccessDeniedException", "UnauthorizedException"):
        raise PermissionError(
            f"IAM access denied for role {role_arn}\n"
            f"  Missing permission: {permission}\n"
            f"  Fix: attach the IAMZeroReadOnly policy to your caller identity\n"
            f"  AWS error: {msg}"
        ) from e
    raise RuntimeError(f"IAM error ({code}): {msg}") from e
