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


def _all_actions(policy: dict) -> list[str]:
    actions = []
    for stmt in policy["Statement"]:
        raw = stmt.get("Action", [])
        actions.extend([raw] if isinstance(raw, str) else raw)
    return actions


def test_removes_only_explicitly_approved_unused_actions():
    used = {"s3:GetObject"}
    findings = [
        {"permission": "s3:PutObject", "recommendation": "remove", "risk": "low"},
        {"permission": "s3:DeleteObject", "recommendation": "keep", "risk": "high"},
    ]
    result = json.loads(generate_minimal_policy(used, findings, [SAMPLE_DOC]))
    actions = _all_actions(result)
    assert "s3:GetObject" in actions
    assert "s3:DeleteObject" in actions
    assert "s3:PutObject" not in actions


def test_missing_model_finding_fails_closed_and_keeps_permission():
    result = json.loads(generate_minimal_policy(set(), [], [SAMPLE_DOC]))
    assert set(_all_actions(result)) == {
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject"
    }


def test_preserves_condition_and_other_statement_semantics():
    docs = [{
        "Statement": [{
            "Sid": "ScopedRead",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::my-bucket/private/*",
            "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-123"}},
        }]
    }]
    findings = [{"permission": "s3:PutObject", "recommendation": "remove"}]
    result = json.loads(generate_minimal_policy({"s3:GetObject"}, findings, docs))
    stmt = result["Statement"][0]
    assert stmt["Sid"] == "ScopedRead"
    assert stmt["Resource"] == "arn:aws:s3:::my-bucket/private/*"
    assert stmt["Condition"] == {"StringEquals": {"aws:SourceVpce": "vpce-123"}}
    assert stmt["Action"] == ["s3:GetObject"]


def test_preserves_explicit_deny_statement():
    docs = [{"Statement": [
        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
    ]}]
    findings = [
        {"permission": "s3:DeleteObject", "recommendation": "remove"},
        {"permission": "s3:GetObject", "recommendation": "remove"},
    ]
    result = json.loads(generate_minimal_policy(set(), findings, docs))
    assert result["Statement"] == [
        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}
    ]


def test_wildcard_with_observed_action_is_retained_for_review():
    docs = [{"Statement": [{
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": "arn:aws:s3:::my-bucket/*",
        "Condition": {"Bool": {"aws:SecureTransport": "true"}},
    }]}]
    findings = [{"permission": "s3:*", "recommendation": "remove", "risk": "low"}]
    result = json.loads(generate_minimal_policy({"s3:GetObject"}, findings, docs))
    assert result["Statement"][0]["Action"] == "s3:*"
    assert result["Statement"][0]["Condition"] == {"Bool": {"aws:SecureTransport": "true"}}


def test_unused_wildcard_can_be_removed_when_explicitly_approved():
    docs = [{"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}]
    findings = [{"permission": "s3:*", "recommendation": "remove", "risk": "low"}]
    result = json.loads(generate_minimal_policy(set(), findings, docs))
    assert result["Statement"] == []
