"""IAM Access Advisor — corroborating signal for CloudTrail gaps.

CloudTrail LookupEvents returns management events only. Data-plane calls
(s3:GetObject, dynamodb:GetItem, sqs:SendMessage, ...) never appear there,
which makes naive "unused" detection dangerously wrong. Access Advisor
(GenerateServiceLastAccessedDetails) reports, per service namespace, when the
role last authenticated — including via data-plane activity. We use it to
protect actions whose service is demonstrably active.
"""
import time

import boto3
from botocore.exceptions import ClientError


def fetch_service_last_accessed(
    role_arn: str,
    profile: str | None = None,
    timeout_seconds: int = 60,
) -> dict[str, str | None]:
    """
    Returns {service_namespace: last_authenticated_iso_or_None}, e.g.
    {"s3": "2026-06-28T09:12:00+00:00", "dynamodb": None}.

    Raises PermissionError with a fix hint if the caller lacks
    iam:GenerateServiceLastAccessedDetails / iam:GetServiceLastAccessedDetails.
    """
    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")

    try:
        job_id = iam.generate_service_last_accessed_details(Arn=role_arn)["JobId"]
    except ClientError as e:
        _raise_advisor_error(e, role_arn)

    deadline = time.monotonic() + timeout_seconds
    result: dict[str, str | None] = {}
    while True:
        try:
            resp = iam.get_service_last_accessed_details(JobId=job_id)
        except ClientError as e:
            _raise_advisor_error(e, role_arn)

        status = resp["JobStatus"]
        if status == "COMPLETED":
            for svc in resp.get("ServicesLastAccessed", []):
                ns = svc["ServiceNamespace"]
                last = svc.get("LastAuthenticated")
                result[ns] = last.isoformat() if last else None
            # Paginate if needed
            marker = resp.get("Marker")
            while resp.get("IsTruncated") and marker:
                resp = iam.get_service_last_accessed_details(JobId=job_id, Marker=marker)
                for svc in resp.get("ServicesLastAccessed", []):
                    ns = svc["ServiceNamespace"]
                    last = svc.get("LastAuthenticated")
                    result[ns] = last.isoformat() if last else None
                marker = resp.get("Marker")
            return result
        if status == "FAILED":
            raise RuntimeError(
                f"Access Advisor job failed: {resp.get('Error', {}).get('Message', 'unknown')}"
            )
        if time.monotonic() > deadline:
            raise RuntimeError("Access Advisor job timed out — try again")
        time.sleep(1)


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
    """
    Splits unused_actions into (truly_unused, protected).

    protected = {action: last_authenticated_iso} for actions whose service
    namespace shows recent authentication per Access Advisor even though no
    per-action CloudTrail event was found — the signature of data-plane usage.
    These must never be recommended for removal outright.
    """
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
