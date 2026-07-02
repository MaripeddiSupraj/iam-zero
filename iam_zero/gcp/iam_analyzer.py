import re

from google.cloud import resourcemanager_v3
from google.api_core.exceptions import PermissionDenied, GoogleAPICallError


def get_service_account_roles(
    service_account: str,
    project: str,
) -> list[str]:
    """
    Returns the list of role IDs currently bound to the service account
    at the project level.
    """
    rm_client = resourcemanager_v3.ProjectsClient()
    resource = f"projects/{project}"

    try:
        policy = rm_client.get_iam_policy(resource=resource)
    except PermissionDenied as e:
        raise PermissionError(
            f"Resource Manager access denied for project {project}\n"
            f"  Missing permission: resourcemanager.projects.getIamPolicy\n"
            f"  Fix: grant the 'Security Reviewer' role to your caller identity\n"
            f"  GCP error: {e.message}"
        ) from e
    except GoogleAPICallError as e:
        raise RuntimeError(f"Resource Manager error: {e.message}") from e

    member = f"serviceAccount:{service_account}"
    roles = []
    for binding in policy.bindings:
        if member in binding.members:
            roles.append(binding.role)
    return sorted(roles)



def _method_service(method: str) -> str:
    """
    Extract the service name from a Cloud Audit Log methodName.

    Handles both short form ('storage.buckets.list' → 'storage') and fully
    qualified protobuf form ('google.logging.v2.LoggingServiceV2.ListLogEntries'
    → 'logging'). Version tokens (v1, v2beta1, ...) and the 'google' prefix
    are skipped.
    """
    _VERSION_RE = re.compile(r"^v\d+[a-z0-9]*$")
    for token in method.split("."):
        t = token.lower()
        if t == "google" or _VERSION_RE.match(t):
            continue
        return t
    return ""


def compute_unused_roles(
    current_roles: list[str],
    used_methods: set[str],
) -> list[str]:
    """
    Returns roles whose permissions don't appear in any of the observed API methods.

    This is a heuristic: GCP method names (e.g. 'storage.buckets.list') don't map
    1:1 to IAM permissions, but the service prefix match is a strong signal.
    """
    used_services = {_method_service(m) for m in used_methods if "." in m}
    used_services.discard("")

    unused = []
    for role in current_roles:
        # Extract service name from role (e.g. 'roles/storage.objectAdmin' → 'storage')
        role_short = role.split("/")[-1]  # 'storage.objectAdmin'
        service = role_short.split(".")[0] if "." in role_short else ""
        if service and service not in used_services:
            unused.append(role)
        elif not service:
            # e.g. 'roles/viewer' — primitive roles are always overly broad; flag for review
            unused.append(role)
    return sorted(unused)
