import json

from iam_zero.aws.policy_generator import combine_policy_documents, generate_minimal_policy


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


def _actions(policy: dict) -> list[str]:
    result = []
    for statement in policy["Statement"]:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        result.extend(actions)
    return result


def test_removes_only_explicitly_approved_unused_action():
    findings = [
        {"permission": "s3:PutObject", "recommendation": "remove", "risk": "low"},
        {"permission": "s3:DeleteObject", "recommendation": "keep", "risk": "high"},
    ]

    policy = json.loads(generate_minimal_policy({"s3:GetObject"}, findings, [SAMPLE_DOC]))

    assert "s3:GetObject" in _actions(policy)
    assert "s3:DeleteObject" in _actions(policy)
    assert "s3:PutObject" not in _actions(policy)


def test_model_cannot_remove_observed_used_action():
    findings = [
        {"permission": "s3:GetObject", "recommendation": "remove", "risk": "low"},
    ]

    policy = json.loads(generate_minimal_policy({"s3:GetObject"}, findings, [SAMPLE_DOC]))

    assert "s3:GetObject" in _actions(policy)


def test_missing_model_finding_defaults_to_keep():
    findings = [
        {"permission": "s3:PutObject", "recommendation": "remove", "risk": "low"},
        # Claude omitted DeleteObject entirely.
    ]

    policy = json.loads(generate_minimal_policy(set(), findings, [SAMPLE_DOC]))

    assert "s3:PutObject" not in _actions(policy)
    assert "s3:DeleteObject" in _actions(policy)


def test_preserves_condition_and_other_statement_fields():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RestrictedRead",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::private/*",
                "Condition": {
                    "StringEquals": {"aws:SourceVpce": "vpce-123"},
                },
            }
        ],
    }

    findings = [{"permission": "s3:PutObject", "recommendation": "remove"}]
    policy = json.loads(generate_minimal_policy({"s3:GetObject"}, findings, [doc]))
    stmt = policy["Statement"][0]

    assert stmt["Action"] == ["s3:GetObject"]
    assert stmt["Resource"] == "arn:aws:s3:::private/*"
    assert stmt["Condition"] == {"StringEquals": {"aws:SourceVpce": "vpce-123"}}
    assert stmt["Sid"] == "RestrictedRead"


def test_preserves_explicit_deny_unchanged():
    deny = {
        "Sid": "DenyOutsideOrg",
        "Effect": "Deny",
        "Action": "s3:*",
        "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-example"}},
    }
    doc = {"Version": "2012-10-17", "Statement": [deny]}

    policy = json.loads(
        generate_minimal_policy(
            set(),
            [{"permission": "s3:*", "recommendation": "remove"}],
            [doc],
        )
    )

    assert policy["Statement"] == [deny]


def test_preserves_notaction_semantics():
    statement = {
        "Effect": "Allow",
        "NotAction": "iam:*",
        "Resource": "*",
    }
    policy = json.loads(generate_minimal_policy(set(), [], [{"Statement": [statement]}]))

    assert policy["Statement"] == [statement]


def test_wildcard_is_never_auto_removed_or_expanded():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::my-bucket/*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}},
            }
        ]
    }
    findings = [{"permission": "s3:*", "recommendation": "remove", "risk": "low"}]

    policy = json.loads(generate_minimal_policy({"s3:GetObject"}, findings, [doc]))
    stmt = policy["Statement"][0]

    assert stmt["Action"] == "s3:*"
    assert stmt["Condition"] == {"Bool": {"aws:SecureTransport": "true"}}


def test_drops_allow_statement_only_when_all_explicit_actions_are_removed():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::bucket/*",
            }
        ]
    }

    policy = json.loads(
        generate_minimal_policy(
            set(),
            [{"permission": "s3:PutObject", "recommendation": "remove"}],
            [doc],
        )
    )

    assert policy["Statement"] == []


def test_empty_original_policy_stays_empty_without_synthesized_grants_or_denies():
    policy = json.loads(generate_minimal_policy({"s3:GetObject"}, [], []))

    assert policy == {"Version": "2012-10-17", "Statement": []}



def test_combine_policy_documents_handles_single_statement_objects():
    docs = [
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            },
        },
        {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*",
                }
            ]
        },
    ]

    combined = combine_policy_documents(docs)

    assert len(combined["Statement"]) == 2
    assert combined["Statement"][0]["Action"] == "s3:GetObject"
    assert combined["Statement"][1]["Effect"] == "Deny"
