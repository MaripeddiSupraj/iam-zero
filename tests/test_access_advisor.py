from datetime import datetime, timezone
from unittest.mock import MagicMock

from iam_zero.aws.access_advisor import (
    AccessEvidence,
    fetch_access_evidence,
    protect_active_services,
)


def test_protects_actions_whose_service_recently_authenticated():
    unused = ["s3:GetObject", "s3:DeleteObject", "dynamodb:GetItem", "sqs:SendMessage"]
    advisor = {"s3": "2026-06-28T09:00:00+00:00", "dynamodb": None}

    truly_unused, protected = protect_active_services(unused, advisor)

    assert protected == {
        "s3:GetObject": "2026-06-28T09:00:00+00:00",
        "s3:DeleteObject": "2026-06-28T09:00:00+00:00",
    }
    assert truly_unused == ["dynamodb:GetItem", "sqs:SendMessage"]


def test_no_advisor_data_protects_nothing():
    unused = ["ec2:StartInstances"]
    truly_unused, protected = protect_active_services(unused, {})
    assert truly_unused == unused
    assert protected == {}


def test_fetch_access_evidence_requests_action_level_and_collects_actions(mocker):
    now = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "IsTruncated": False,
        "ServicesLastAccessed": [
            {
                "ServiceNamespace": "s3",
                "LastAuthenticated": now,
                "TrackedActionsLastAccessed": [
                    {
                        "ActionName": "ListBucket",
                        "LastAccessedTime": now,
                    },
                    {
                        "ActionName": "PutBucketAcl",
                        "LastAccessedTime": None,
                    },
                ],
            }
        ],
    }
    session = MagicMock()
    session.client.return_value = iam
    mocker.patch("iam_zero.aws.access_advisor.boto3.Session", return_value=session)

    evidence = fetch_access_evidence("arn:aws:iam::123456789012:role/example")

    iam.generate_service_last_accessed_details.assert_called_once_with(
        Arn="arn:aws:iam::123456789012:role/example",
        Granularity="ACTION_LEVEL",
    )
    assert evidence == AccessEvidence(
        service_last_accessed={"s3": "2026-09-01T10:00:00+00:00"},
        action_last_accessed={"s3:ListBucket": "2026-09-01T10:00:00+00:00"},
    )


def test_fetch_access_evidence_paginates(mocker):
    now = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.side_effect = [
        {
            "JobStatus": "COMPLETED",
            "IsTruncated": True,
            "Marker": "next",
            "ServicesLastAccessed": [
                {"ServiceNamespace": "ec2", "LastAuthenticated": now},
            ],
        },
        {
            "JobStatus": "COMPLETED",
            "IsTruncated": False,
            "ServicesLastAccessed": [
                {"ServiceNamespace": "s3", "LastAuthenticated": now},
            ],
        },
    ]
    session = MagicMock()
    session.client.return_value = iam
    mocker.patch("iam_zero.aws.access_advisor.boto3.Session", return_value=session)

    evidence = fetch_access_evidence("arn:aws:iam::123456789012:role/example")

    assert set(evidence.service_last_accessed) == {"ec2", "s3"}
    assert iam.get_service_last_accessed_details.call_count == 2
