from unittest.mock import MagicMock

from iam_zero.aws.iam_analyzer import _allow_actions, compute_unused, get_role_policies



def test_compute_unused_basic():
    current = ["s3:GetObject", "s3:PutObject", "ec2:DescribeInstances"]
    used = {"s3:GetObject", "ec2:DescribeInstances"}
    result = compute_unused(current, used)
    assert result == ["s3:PutObject"]


def test_compute_unused_all_used():
    current = ["s3:GetObject", "s3:PutObject"]
    used = {"s3:GetObject", "s3:PutObject"}
    assert compute_unused(current, used) == []


def test_compute_unused_wildcards_always_flagged():
    current = ["s3:*", "ec2:DescribeInstances"]
    used = {"ec2:DescribeInstances"}
    result = compute_unused(current, used)
    assert "s3:*" in result


def test_compute_unused_global_wildcard_flagged():
    current = ["*", "s3:GetObject"]
    used = {"s3:GetObject"}
    result = compute_unused(current, used)
    assert "*" in result



def test_allow_actions_handles_single_statement_and_ignores_notaction():
    doc = {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "NotAction": "iam:*",
            "Resource": "*",
        }
    }
    assert _allow_actions(doc) == set()

    doc["Statement"].pop("NotAction")
    assert _allow_actions(doc) == {"s3:GetObject"}


def test_compute_unused_is_case_insensitive():
    assert compute_unused(["s3:GetObject"], {"S3:getobject"}) == []


def test_get_role_policies_paginates_attached_and_inline(mocker):
    iam = MagicMock()

    attached = MagicMock()
    attached.paginate.return_value = [
        {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123:policy/one"}]},
        {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123:policy/two"}]},
    ]
    inline = MagicMock()
    inline.paginate.return_value = [
        {"PolicyNames": ["inline-one"]},
        {"PolicyNames": ["inline-two"]},
    ]

    def paginator(name):
        return {
            "list_attached_role_policies": attached,
            "list_role_policies": inline,
        }[name]

    iam.get_paginator.side_effect = paginator
    iam.get_policy.side_effect = [
        {"Policy": {"DefaultVersionId": "v1"}},
        {"Policy": {"DefaultVersionId": "v2"}},
    ]
    iam.get_policy_version.side_effect = [
        {
            "PolicyVersion": {
                "Document": {
                    "Statement": {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                }
            }
        },
        {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "ec2:DescribeInstances",
                            "Resource": "*",
                        }
                    ]
                }
            }
        },
    ]
    iam.get_role_policy.side_effect = [
        {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "logs:CreateLogStream",
                    "Resource": "*",
                }
            }
        },
        {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "Deny",
                    "Action": "iam:*",
                    "Resource": "*",
                }
            }
        },
    ]

    session = MagicMock()
    session.client.return_value = iam
    mocker.patch("iam_zero.aws.iam_analyzer.boto3.Session", return_value=session)

    actions, docs = get_role_policies("arn:aws:iam::123:role/example")

    assert actions == [
        "ec2:DescribeInstances",
        "logs:CreateLogStream",
        "s3:GetObject",
    ]
    assert len(docs) == 4
    assert attached.paginate.call_count == 1
    assert inline.paginate.call_count == 1
