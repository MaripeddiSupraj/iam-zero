import json
from iam_zero.aws.policy_generator import generate_minimal_policy


SAMPLE_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}


def test_keeps_used_actions():
    used = {"s3:GetObject"}
    findings = [
        {"permission": "s3:PutObject", "recommendation": "remove", "risk": "low", "reason": "unused"},
        {"permission": "s3:DeleteObject", "recommendation": "keep", "risk": "high", "reason": "dr"},
    ]
    result = json.loads(generate_minimal_policy(used, findings, [SAMPLE_DOC]))
    actions = [a for s in result["Statement"] for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])]
    assert "s3:GetObject" in actions
    assert "s3:DeleteObject" in actions
    assert "s3:PutObject" not in actions


def test_empty_statements_when_nothing_kept():
    used: set[str] = set()
    findings = [
        {"permission": "s3:GetObject", "recommendation": "remove", "risk": "low", "reason": "unused"},
    ]
    # No overlap → no Allow statements, and never a Deny-all
    result = json.loads(generate_minimal_policy(used, findings, [SAMPLE_DOC]))
    assert result["Statement"] == []


def test_wildcard_covered_used_actions_are_not_dropped():
    """A role with only 's3:*' where s3:GetObject was used must keep s3:GetObject."""
    from iam_zero.aws.policy_generator import generate_minimal_policy
    import json

    docs = [{"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::my-bucket/*"}]}]
    findings = [{"permission": "s3:*", "recommendation": "remove", "risk": "low", "reason": ""}]
    policy = json.loads(generate_minimal_policy({"s3:GetObject"}, findings, docs))

    all_actions = [a for s in policy["Statement"] for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])]
    assert "s3:GetObject" in all_actions
    resources = [s["Resource"] for s in policy["Statement"] if "s3:GetObject" in s["Action"]]
    assert resources == [["arn:aws:s3:::my-bucket/*"]]


def test_no_deny_all_fallback():
    from iam_zero.aws.policy_generator import generate_minimal_policy
    import json

    policy = json.loads(generate_minimal_policy(set(), [], []))
    for stmt in policy["Statement"]:
        assert stmt.get("Effect") != "Deny"
