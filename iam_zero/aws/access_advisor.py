"""AWS IAM last-accessed evidence.

iam-zero requests ACTION_LEVEL reports so tracked management-action activity can
corroborate CloudTrail. Service-level activity is retained as a conservative
safety signal for actions whose exact usage is not observable (including data
plane actions, which IAM action-last-accessed does not track).
"""

from dataclasses import dataclass
import time

import boto3
from botocore.exceptions import ClientError


@dataclass(frozen=True)
class AccessEvidence:
    service_last_accessed: dict[str, str | None]
    action_last_accessed: dict[str, str]


def fetch_access_evidence(
    role_arn: str,
    profile: str | None = None,
    timeout_seconds: int = 60,
) -> AccessEvidence:
    """Fetch service + tracked action last-accessed evidence for an IAM role."""
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
    while True:
        try:
            response = iam.get_service_last_accessed_details(JobId=job_id)
        except ClientError as e:
            _raise_advisor_error(e, role_arn)

        status = response["JobStatus"]
        if status == "COMPLETED":
            return _collect_pages(iam, job_id, response)
        if status == "FAILED":
            raise RuntimeError(
                f"Access Advisor job failed: "
                f"{response.get('Error', {}).get('Message', 'unknown')}"
            )
        if time.monotonic() > deadline:
            raise RuntimeError("Access Advisor job timed out — try again")
        time.sleep(1)


def _collect_pages(iam, job_id: str, first_response: dict) -> AccessEvidence:
    services: dict[str, str | None] = {}
    actions: dict[str, str] = {}
    response = first_response

    while True:
        for service in response.get("ServicesLastAccessed", []):
            namespace = service.get("ServiceNamespace", "")
            if not namespace:
                continue

            last = service.get("LastAuthenticated")
            services[namespace.lower()] = last.isoformat() if last else None

            for tracked in service.get("TrackedActionsLastAccessed", []) or []:
                action_name = tracked.get("ActionName")
                action_time = tracked.get("LastAccessedTime")
                if action_name and action_time:
                    actions[f"{namespace}:{action_name}"] = action_time.isoformat()

        if not response.get("IsTruncated"):
            break
        marker = response.get("Marker")
        if not marker:
            raise RuntimeError(
                "Access Advisor returned a truncated response without a pagination marker"
            )
        try:
            response = iam.get_service_last_accessed_details(
                JobId=job_id,
                Marker=marker,
            )
        except ClientError as e:
            raise RuntimeError(f"Access Advisor pagination failed: {e}") from e

    return AccessEvidence(
        service_last_accessed=services,
        action_last_accessed=actions,
    )


def fetch_service_last_accessed(
    role_arn: str,
    profile: str | None = None,
    timeout_seconds: int = 60,
) -> dict[str, str | None]:
    """Backward-compatible service-only view of :func:`fetch_access_evidence`."""
    return fetch_access_evidence(
        role_arn,
        profile=profile,
        timeout_seconds=timeout_seconds,
    ).service_last_accessed


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
    """Protect candidate actions in services with observed authenticated use.

    Service-level evidence deliberately errs on the side of keeping access:
    absence of an action-level record is not proof that an action is unused,
    especially for data-plane operations.
    """
    truly_unused: list[str] = []
    protected: dict[str, str] = {}

    for action in unused_actions:
        service = action.split(":", 1)[0].lower() if ":" in action else ""
        last = service_last_accessed.get(service)
        if last:
            protected[action] = last
        else:
            truly_unused.append(action)

    return truly_unused, protected
