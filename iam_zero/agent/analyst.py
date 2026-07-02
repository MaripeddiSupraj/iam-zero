import json

import anthropic

MODEL = "claude-sonnet-4-20250514"

_VALID_RECOMMENDATIONS = {"remove", "keep", "investigate"}
_VALID_RISKS = {"low", "medium", "high"}


def _extract_json_array(raw: str) -> list[dict]:
    """Robustly pull the first JSON array out of a model response."""
    start = raw.find("[")
    end = raw.rfind("]")
    if start == -1 or end == -1 or end < start:
        raise ValueError(f"Claude did not return a JSON array. Raw response:\n{raw[:500]}")
    return json.loads(raw[start : end + 1])


def _validate_findings(items: list[dict]) -> list[dict]:
    findings = []
    for item in items:
        if not isinstance(item, dict) or "permission" not in item:
            continue
        rec = str(item.get("recommendation", "investigate")).lower()
        risk = str(item.get("risk", "medium")).lower()
        findings.append(
            {
                "permission": item["permission"],
                "recommendation": rec if rec in _VALID_RECOMMENDATIONS else "investigate",
                "risk": risk if risk in _VALID_RISKS else "medium",
                "reason": str(item.get("reason", "")).strip(),
                "last_used": item.get("last_used"),
            }
        )
    return findings


def _run(client: anthropic.Anthropic, prompt: str) -> list[dict]:
    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        messages=[
            {"role": "user", "content": prompt},
            # Prefill forces the array to start immediately — no prose, no fences.
            {"role": "assistant", "content": "["},
        ],
    )
    raw = "[" + response.content[0].text
    return _validate_findings(_extract_json_array(raw))


def analyze_aws_permissions(
    client: anthropic.Anthropic,
    role_arn: str,
    current_permissions: list[str],
    used_permissions: list[str],
    unused_permissions: list[str],
    days: int,
    protected_actions: dict[str, str] | None = None,
) -> list[dict]:
    protected_actions = protected_actions or {}
    protected_block = ""
    if protected_actions:
        protected_block = (
            "\nIMPORTANT — Access Advisor shows these services WERE recently authenticated "
            "even though no per-action CloudTrail event exists (data-plane usage is invisible "
            "to CloudTrail LookupEvents). These actions must be 'keep' or 'investigate', "
            "NEVER 'remove':\n"
            f"{json.dumps(protected_actions, indent=2)}\n"
        )

    prompt = f"""You are an AWS IAM security analyst. Analyze unused IAM permissions and assess removal safety.

Role ARN: {role_arn}
Current permissions: {json.dumps(sorted(current_permissions))}
Permissions actually used (last {days} days, CloudTrail management events): {json.dumps(sorted(used_permissions))}
Unused permissions (candidates for removal): {json.dumps(sorted(unused_permissions))}
{protected_block}
For each unused permission, assess:
1. Is it safe to remove? recommendation: "remove", "keep", or "investigate"
2. Brief reasoning (1–2 sentences)
3. Risk if removed incorrectly: "low", "medium", or "high"

Consider: some permissions are used infrequently (e.g., disaster recovery, year-end processes).
If a permission sounds like it could be used rarely but critically, mark "investigate" not "remove".
CloudTrail LookupEvents does NOT record data-plane events — be conservative with data-plane
actions (s3:GetObject, dynamodb:GetItem, sqs:SendMessage, kinesis:PutRecord, etc).

Return a JSON array only — no prose, no markdown. Example:
[
  {{"permission": "s3:DeleteObject", "recommendation": "remove", "risk": "low", "reason": "No deletes observed; typical read-only workload."}},
  {{"permission": "iam:PassRole", "recommendation": "investigate", "risk": "high", "reason": "Used for delegation; absence in logs may indicate infrequent use."}}
]"""

    findings = _run(client, prompt)

    # Hard guarantee: protected actions can never come back as "remove",
    # regardless of what the model said.
    for f in findings:
        if f["permission"] in protected_actions:
            if f["recommendation"] == "remove":
                f["recommendation"] = "investigate"
                f["reason"] = (
                    "Service recently authenticated per Access Advisor (likely data-plane "
                    "usage invisible to CloudTrail). " + f["reason"]
                ).strip()
            f["last_used"] = protected_actions[f["permission"]]
    return findings


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

Note: Data Access audit logs are disabled by default in GCP. If the observed methods
look sparse, read-heavy roles (storage/bigquery viewers) may be in active use without
appearing in logs — prefer "investigate" over "remove" for those.

Return a JSON array only — no prose, no markdown. Example:
[
  {{"permission": "roles/storage.objectAdmin", "recommendation": "remove", "risk": "low", "reason": "No GCS API calls observed in logs."}},
  {{"permission": "roles/iam.serviceAccountTokenCreator", "recommendation": "investigate", "risk": "high", "reason": "Token creation may be used by downstream services not visible in these logs."}}
]"""

    return _run(client, prompt)
