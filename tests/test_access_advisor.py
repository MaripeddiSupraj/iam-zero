from iam_zero.aws.access_advisor import protect_active_services


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
