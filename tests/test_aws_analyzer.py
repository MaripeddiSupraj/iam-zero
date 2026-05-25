import pytest
from iam_zero.aws.iam_analyzer import compute_unused


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
