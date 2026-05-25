import re
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError


def _event_source_to_prefix(event_source: str) -> str:
    """Convert 'ec2.amazonaws.com' → 'ec2:'"""
    service = event_source.replace(".amazonaws.com", "")
    return f"{service}:"


def fetch_used_actions(
    role_arn: str,
    days: int,
    profile: str | None = None,
    region: str | None = None,
) -> set[str]:
    """
    Returns a set of IAM action strings (e.g. 's3:GetObject') that the role
    actually invoked over the last `days` days, based on CloudTrail events.
    """
    session = boto3.Session(profile_name=profile)
    kwargs: dict = {}
    if region:
        kwargs["region_name"] = region

    ct = session.client("cloudtrail", **kwargs)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    lookup_attrs = [{"AttributeKey": "Username", "AttributeValue": _role_name(role_arn)}]

    actions: set[str] = set()
    paginator_kwargs = {
        "LookupAttributes": lookup_attrs,
        "StartTime": start,
        "EndTime": end,
        "MaxResults": 50,
    }

    try:
        paginator = ct.get_paginator("lookup_events")
        for page in paginator.paginate(**paginator_kwargs):
            for event in page.get("Events", []):
                source = event.get("EventSource", "")
                name = event.get("EventName", "")
                if source and name:
                    prefix = _event_source_to_prefix(source)
                    actions.add(f"{prefix}{name}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        if code in ("AccessDeniedException", "UnauthorizedException"):
            raise PermissionError(
                f"CloudTrail access denied for role {role_arn}\n"
                f"  Missing permission: cloudtrail:LookupEvents\n"
                f"  Fix: attach the IAMZeroReadOnly policy to your caller identity\n"
                f"  AWS error: {msg}"
            ) from e
        raise RuntimeError(f"CloudTrail error ({code}): {msg}") from e

    return actions


def _role_name(role_arn: str) -> str:
    """Extract role name from ARN for CloudTrail lookup."""
    return role_arn.split("/")[-1]
