from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError


_EVENT_SOURCE_PREFIX_ALIASES = {
    "monitoring": "cloudwatch",
}


def _event_source_to_prefix(event_source: str) -> str:
    """Convert a CloudTrail event source to its IAM action prefix."""
    service = event_source.removesuffix(".amazonaws.com")
    service = _EVENT_SOURCE_PREFIX_ALIASES.get(service, service)
    return f"{service}:"


def _normalize_regions(region) -> list[str | None]:
    if not region:
        return [None]
    if isinstance(region, str):
        return [region]
    values = [value for value in region if value]
    return values or [None]


def fetch_used_actions(
    role_arn: str,
    days: int,
    profile: str | None = None,
    region: str | tuple[str, ...] | list[str] | None = None,
) -> set[str]:
    """Return observed management actions from regional CloudTrail history.

    LookupEvents covers recent management events only. For assumed roles the
    Username field can be the session name instead of the IAM role name, so
    this is a supplemental signal; Access Advisor remains required by default.
    """
    session = boto3.Session(profile_name=profile)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    lookup_attrs = [{"AttributeKey": "Username", "AttributeValue": _role_name(role_arn)}]

    actions: set[str] = set()
    for region_name in _normalize_regions(region):
        kwargs: dict = {}
        if region_name:
            kwargs["region_name"] = region_name
        client = session.client("cloudtrail", **kwargs)

        paginator_kwargs = {
            "LookupAttributes": lookup_attrs,
            "StartTime": start,
            "EndTime": end,
            "MaxResults": 50,
        }

        try:
            paginator = client.get_paginator("lookup_events")
            for page in paginator.paginate(**paginator_kwargs):
                for event in page.get("Events", []):
                    source = event.get("EventSource", "")
                    name = event.get("EventName", "")
                    if source and name:
                        actions.add(f"{_event_source_to_prefix(source)}{name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"]["Message"]
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedException"):
                raise PermissionError(
                    f"CloudTrail access denied for role {role_arn}\n"
                    f"  Missing permission: cloudtrail:LookupEvents\n"
                    f"  Fix: attach the IAMZeroReadOnly policy to your caller identity\n"
                    f"  AWS error: {msg}"
                ) from e
            raise RuntimeError(
                f"CloudTrail error in region {region_name or 'default'} ({code}): {msg}"
            ) from e

    return actions


def _role_name(role_arn: str) -> str:
    """Extract role name from ARN for the supplemental CloudTrail lookup."""
    return role_arn.split("/")[-1]
