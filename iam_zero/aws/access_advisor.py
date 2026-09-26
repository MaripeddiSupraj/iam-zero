"""AWS IAM Access Advisor evidence.

CloudTrail LookupEvents is useful for management events but is incomplete for
role usage and data-plane activity. IAM Access Advisor can produce action-level
last-accessed data for tracked actions and service-level last-authenticated data.
iam-zero uses both as conservative evidence before suggesting removals.
"""
import time

import boto3
from botocore.exceptions import ClientError


def fetch_access_evidence(
    role_arn: str,
    profile: str | None = None,
    timeout_seconds: int = 60,
) -> tuple[dict[str, str | None], dict[str, str]]:
    """Return service-level and action-level last-accessed evidence.

    Action keys are normalized IAM action strings such as s3:GetObject.
    Only AWS-tracked actions appear at action level, so service evidence is
    retained as a conservative fallback.
    """
    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")

    try:
        job_id = iam.generate_service_last_accessed_details(
            Arn=role_arn,
            Granularity="ACTION_LEVEL",
        )["JobId"]
    except ClientError as e:
        _raise_advisor_error(e, role_arn)

    deadline = time.monotonic() + timeout_seconds
    services: dict[str, str | None] = {}
    actions: dict[str, str] = {}

    while True:
        try:
            resp = iam.get_service_last_accessed_details(JobId=job_id)
        except ClientError as e:
            _raise_advisor_error(e, role_arn)

        status = resp["JobStatus"]
        if status == "COMPLETED":
            _collect_access_evidence(resp, services, actions)

            marker = resp.get("Marker")
            while resp.get("IsTruncated") and marker:
                try:
                    resp = iam.get_service_last_accessed_details(
                        JobId=job_id,
                        Marker=marker,
                    )
                except ClientError as e:
                    _raise_advisor_error(e, role_arn)
                _collect_access_evidence(resp, services, actions)
                marker = resp.get("Marker")

            return services, actions

        if status == "FAILED":
            raise RuntimeError(
                f"Access Advisor job failed: {resp.get('Error', {}).get('Message', 'unknown')}"
            )
        if time.monotonic() > deadline:
            raise RuntimeError("Access Advisor job timed out — try again")
        time.sleep(1)


def _collect_access_evidence(
    resp: dict,
    services: dict[str, str | None],
    actions: dict[str, str],
) -> None:
    for svc in resp.get("ServicesLastAccessed", []):
        namespace = svc["ServiceNamespace"]
        last = svc.get("LastAuthenticated")
        services[namespace] = last.isoformat() if last else None

        for tracked in svc.get("TrackedActionsLastAccessed", []) or []:
            action_name = tracked.get("ActionName")
            action_last = tracked.get("LastAccessedTime")
            if not action_name or not action_last:
                continue
            action = action_name if ":" in action_name else f"{namespace}:{action_name}"
            actions[action] = action_last.isoformat()


def fetch_service_last_accessed(
    role_arn: str,
    profile: str | None = None,
    timeout_seconds: int = 60,
) -> dict[str, str | None]:
    """Backward-compatible service-only view of Access Advisor evidence."""
    services, _ = fetch_access_evidence(
        role_arn,
        profile=profile,
        timeout_seconds=timeout_seconds,
    )
    return services


def _raise_advisor_error(e: ClientError, role_arn: str) -> None:
    code = e.response["Error"]["Code"]
    msg = e.response["Error"]["Message"]
    if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedException"):
        raise PermissionError(
            f"Access Advisor denied for role {role_arn}\n"
            f"  Missing permission: iam:GenerateServiceLastAccessedDetails, "
            f"iam:GetServiceLastAccessedDetails\n"
            f"  Fix: attach these read-only IAM permissions to your caller identity\n"
            f"  AWS error: {msg}"
        ) from e
    raise RuntimeError(f"Access Advisor error ({code}): {msg}") from e


def protect_active_services(
    unused_actions: list[str],
    service_last_accessed: dict[str, str | None],
) -> tuple[list[str], dict[str, str]]:
    """Split candidates into truly-unused and service-active protected actions."""
    truly_unused: list[str] = []
    protected: dict[str, str] = {}
    for action in unused_actions:
        service = action.split(":")[0].lower() if ":" in action else ""
        last = service_last_accessed.get(service)
        if last:
            protected[action] = last
        else:
            truly_unused.append(action)
    return truly_unused, protected
