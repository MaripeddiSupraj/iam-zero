import pytest
from iam_zero.gcp.iam_analyzer import compute_unused_roles


def test_unused_role_no_service_match():
    roles = ["roles/storage.objectAdmin", "roles/compute.viewer"]
    used_methods = {"bigquery.datasets.get", "bigquery.tables.list"}
    result = compute_unused_roles(roles, used_methods)
    assert "roles/storage.objectAdmin" in result
    assert "roles/compute.viewer" in result


def test_used_role_not_flagged():
    roles = ["roles/storage.objectAdmin", "roles/compute.viewer"]
    used_methods = {"storage.objects.get", "storage.buckets.list"}
    result = compute_unused_roles(roles, used_methods)
    assert "roles/storage.objectAdmin" not in result
    assert "roles/compute.viewer" in result


def test_primitive_role_flagged():
    roles = ["roles/viewer", "roles/storage.objectAdmin"]
    used_methods = {"storage.objects.get"}
    result = compute_unused_roles(roles, used_methods)
    assert "roles/viewer" in result


def test_empty_roles():
    assert compute_unused_roles([], {"storage.objects.get"}) == []


def test_empty_methods():
    roles = ["roles/storage.objectAdmin"]
    result = compute_unused_roles(roles, set())
    assert "roles/storage.objectAdmin" in result
