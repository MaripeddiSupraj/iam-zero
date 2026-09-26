from unittest.mock import MagicMock

from iam_zero.aws.cloudtrail import fetch_used_actions, _event_source_to_prefix, _role_name


def test_event_source_to_prefix():
    assert _event_source_to_prefix("s3.amazonaws.com") == "s3:"
    assert _event_source_to_prefix("ec2.amazonaws.com") == "ec2:"
    assert _event_source_to_prefix("iam.amazonaws.com") == "iam:"\n    assert _event_source_to_prefix("monitoring.amazonaws.com") == "cloudwatch:"


def test_role_name():
    assert _role_name("arn:aws:iam::123456789012:role/my-role") == "my-role"
    assert _role_name("arn:aws:iam::123456789012:role/path/my-role") == "my-role"


def test_fetch_used_actions_empty(mocker):
    mock_ct = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Events": []}]
    mock_ct.get_paginator.return_value = mock_paginator

    mock_session = MagicMock()
    mock_session.client.return_value = mock_ct
    mocker.patch("iam_zero.aws.cloudtrail.boto3.Session", return_value=mock_session)

    result = fetch_used_actions("arn:aws:iam::123:role/test-role", days=7)
    assert result == set()


def test_fetch_used_actions_parses_events(mocker):
    mock_ct = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {
            "Events": [
                {"EventSource": "s3.amazonaws.com", "EventName": "GetObject"},
                {"EventSource": "ec2.amazonaws.com", "EventName": "DescribeInstances"},
                {"EventSource": "s3.amazonaws.com", "EventName": "GetObject"},  # duplicate
            ]
        }
    ]
    mock_ct.get_paginator.return_value = mock_paginator

    mock_session = MagicMock()
    mock_session.client.return_value = mock_ct
    mocker.patch("iam_zero.aws.cloudtrail.boto3.Session", return_value=mock_session)

    result = fetch_used_actions("arn:aws:iam::123:role/test-role", days=7)
    assert "s3:GetObject" in result
    assert "ec2:DescribeInstances" in result
    assert len(result) == 2


def test_fetch_used_actions_unions_multiple_regions(mocker):
    east = MagicMock()
    east_paginator = MagicMock()
    east_paginator.paginate.return_value = [
        {"Events": [{"EventSource": "ec2.amazonaws.com", "EventName": "DescribeInstances"}]}
    ]
    east.get_paginator.return_value = east_paginator

    west = MagicMock()
    west_paginator = MagicMock()
    west_paginator.paginate.return_value = [
        {"Events": [{"EventSource": "s3.amazonaws.com", "EventName": "ListBucket"}]}
    ]
    west.get_paginator.return_value = west_paginator

    session = MagicMock()

    def client(_service, **kwargs):
        return {
            "us-east-1": east,
            "us-west-2": west,
        }[kwargs["region_name"]]

    session.client.side_effect = client
    mocker.patch("iam_zero.aws.cloudtrail.boto3.Session", return_value=session)

    result = fetch_used_actions(
        "arn:aws:iam::123:role/test-role",
        days=7,
        region=("us-east-1", "us-west-2"),
    )

    assert result == {"ec2:DescribeInstances", "s3:ListBucket"}
