import json
import pytest
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


def test_empty_policy_when_nothing_kept():
    used: set[str] = set()
    findings = [
        {"permission": "s3:GetObject", "recommendation": "remove", "risk": "low", "reason": "unused"},
    ]
    # No overlap → deny-all policy
    result = json.loads(generate_minimal_policy(used, findings, [SAMPLE_DOC]))
    stmt = result["Statement"][0]
    assert stmt["Effect"] == "Deny"
