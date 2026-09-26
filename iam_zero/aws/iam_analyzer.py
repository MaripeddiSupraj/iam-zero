import boto3
from botocore.exceptions import ClientError


def _allow_actions(document: dict) -> set[str]:
    """Extract explicit Allow Action entries from an IAM policy document."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    actions: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        # NotAction has inverse semantics and must not be treated as an explicit
        # set of granted actions by the unused-action analyzer.
        if "NotAction" in statement:
            continue
        statement_actions = statement.get("Action", [])
        if isinstance(statement_actions, str):
            statement_actions = [statement_actions]
        for action in statement_actions:
            if isinstance(action, str):
                actions.add(action)
    return actions


def get_role_policies(
    role_arn: str,
    profile: str | None = None,
) -> tuple[list[str], list[dict]]:
    """Return explicit allowed actions and raw identity policy documents.

    Both attached managed policies and inline role policies are fully
    paginated. Raw documents are retained for safety-preserving policy
    generation; conditions, denies and other statement semantics are not
    discarded here.
    """
    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")
    role_name = role_arn.split("/")[-1]

    actions: set[str] = set()
    raw_docs: list[dict] = []

    try:
        attached_paginator = iam.get_paginator("list_attached_role_policies")
        for page in attached_paginator.paginate(RoleName=role_name):
            for policy_ref in page.get("AttachedPolicies", []):
                policy_arn = policy_ref["PolicyArn"]
                try:
                    version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"][
                        "DefaultVersionId"
                    ]
                    doc = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id,
                    )["PolicyVersion"]["Document"]
                except ClientError as e:
                    _raise_iam_error(
                        e,
                        role_arn,
                        "iam:GetPolicy / iam:GetPolicyVersion",
                    )

                raw_docs.append(doc)
                actions.update(_allow_actions(doc))
    except ClientError as e:
        _raise_iam_error(e, role_arn, "iam:ListAttachedRolePolicies")

    try:
        inline_paginator = iam.get_paginator("list_role_policies")
        for page in inline_paginator.paginate(RoleName=role_name):
            for name in page.get("PolicyNames", []):
                try:
                    doc = iam.get_role_policy(
                        RoleName=role_name,
                        PolicyName=name,
                    )["PolicyDocument"]
                except ClientError as e:
                    _raise_iam_error(e, role_arn, "iam:GetRolePolicy")

                raw_docs.append(doc)
                actions.update(_allow_actions(doc))
    except ClientError as e:
        _raise_iam_error(e, role_arn, "iam:ListRolePolicies")

    return sorted(actions), raw_docs


def list_roles(profile: str | None = None) -> list[str]:
    """Return all customer-manageable IAM role ARNs in the account."""
    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")
    roles: list[str] = []

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            path = role.get("Path", "/")
            if path.startswith("/aws-service-role/"):
                continue
            roles.append(role["Arn"])

    return sorted(roles)


def compute_unused(
    current_actions: list[str],
    used_actions: set[str],
) -> list[str]:
    """Return explicit policy actions with no matching observed action.

    Wildcards remain candidates for *review* so the UI can call them out, but
    downstream safety guards never auto-remove wildcard permissions.
    """
    used_lower = {action.lower() for action in used_actions}
    unused = []

    for action in current_actions:
        if "*" in action or "?" in action:
            unused.append(action)
            continue
        if action.lower() not in used_lower:
            unused.append(action)

    return sorted(unused)


def _raise_iam_error(e: ClientError, role_arn: str, permission: str) -> None:
    code = e.response["Error"]["Code"]
    msg = e.response["Error"]["Message"]
    if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedException"):
        raise PermissionError(
            f"IAM access denied for role {role_arn}\n"
            f"  Missing permission: {permission}\n"
            f"  Fix: attach the IAMZeroReadOnly policy to your caller identity\n"
            f"  AWS error: {msg}"
        ) from e
    raise RuntimeError(f"IAM error ({code}): {msg}") from e
