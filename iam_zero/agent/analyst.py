import json
import anthropic

MODEL = "claude-sonnet-4-20250514"


def analyze_aws_permissions(
    client: anthropic.Anthropic,
    role_arn: str,
    current_permissions: list[str],
    used_permissions: list[str],
    unused_permissions: list[str],
    days: int,
) -> list[dict]:
    prompt = f"""You are an AWS IAM security analyst. Analyze unused IAM permissions and assess removal safety.

Role ARN: {role_arn}
Current permissions: {json.dumps(sorted(current_permissions))}
Permissions actually used (last {days} days): {json.dumps(sorted(used_permissions))}
Unused permissions (candidates for removal): {json.dumps(sorted(unused_permissions))}

For each unused permission, assess:
1. Is it safe to remove? recommendation: "remove", "keep", or "investigate"
2. Brief reasoning (1–2 sentences)
3. Risk if removed incorrectly: "low", "medium", or "high"

Consider: some permissions are used infrequently (e.g., disaster recovery, year-end processes).
If a permission sounds like it could be used rarely but critically, mark "investigate" not "remove".

Return a JSON array only — no prose, no markdown. Example:
[
  {{"permission": "s3:DeleteObject", "recommendation": "remove", "risk": "low", "reason": "No deletes observed; typical read-only workload."}},
  {{"permission": "iam:PassRole", "recommendation": "investigate", "risk": "high", "reason": "Used for delegation; absence in logs may indicate infrequent use."}}
]"""

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())


def analyze_gcp_permissions(
    client: anthropic.Anthropic,
    service_account: str,
    current_roles: list[str],
    used_methods: list[str],
    unused_roles: list[str],
    days: int,
) -> list[dict]:
    prompt = f"""You are a GCP IAM security analyst. Analyze unused IAM roles for a service account.

Service Account: {service_account}
Current roles: {json.dumps(sorted(current_roles))}
API methods actually called (last {days} days): {json.dumps(sorted(used_methods))}
Roles with no observed usage: {json.dumps(sorted(unused_roles))}

For each unused role, assess:
1. Is it safe to remove? recommendation: "remove", "keep", or "investigate"
2. Brief reasoning (1–2 sentences)
3. Risk if removed incorrectly: "low", "medium", or "high"

Return a JSON array only — no prose, no markdown. Example:
[
  {{"permission": "roles/storage.objectAdmin", "recommendation": "remove", "risk": "low", "reason": "No GCS API calls observed in logs."}},
  {{"permission": "roles/iam.serviceAccountTokenCreator", "recommendation": "investigate", "risk": "high", "reason": "Token creation may be used by downstream services not visible in these logs."}}
]"""

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())
