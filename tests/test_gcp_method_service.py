from iam_zero.gcp.iam_analyzer import _method_service, compute_unused_roles


def test_short_form():
    assert _method_service("storage.buckets.list") == "storage"


def test_fully_qualified_protobuf_form():
    assert _method_service("google.logging.v2.LoggingServiceV2.ListLogEntries") == "logging"


def test_versioned_prefix():
    assert _method_service("v1.compute.instances.list") == "compute"


def test_qualified_methods_do_not_flag_active_roles_unused():
    roles = ["roles/logging.viewer", "roles/storage.objectAdmin"]
    methods = {"google.logging.v2.LoggingServiceV2.ListLogEntries"}
    unused = compute_unused_roles(roles, methods)
    assert "roles/logging.viewer" not in unused
    assert "roles/storage.objectAdmin" in unused
