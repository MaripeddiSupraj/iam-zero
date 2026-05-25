from datetime import datetime, timedelta, timezone

from google.cloud import logging as gcp_logging
from google.api_core.exceptions import PermissionDenied, GoogleAPICallError


def fetch_used_methods(
    service_account: str,
    project: str,
    days: int,
) -> set[str]:
    """
    Returns a set of GCP API methodNames the service account actually called
    over the last `days` days, sourced from Cloud Audit Logs.
    """
    client = gcp_logging.Client(project=project)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    # ISO 8601 timestamps for the filter
    start_str = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end.strftime("%Y-%m-%dT%H:%M:%SZ")

    log_filter = (
        f'protoPayload.authenticationInfo.principalEmail="{service_account}" '
        f'logName=("projects/{project}/logs/cloudaudit.googleapis.com%2Factivity" OR '
        f'"projects/{project}/logs/cloudaudit.googleapis.com%2Fdata_access") '
        f'timestamp>="{start_str}" '
        f'timestamp<="{end_str}"'
    )

    methods: set[str] = set()
    try:
        for entry in client.list_entries(filter_=log_filter, page_size=1000):
            proto = entry.payload if hasattr(entry, "payload") else {}
            if isinstance(proto, dict):
                method = proto.get("methodName", "")
            else:
                # proto_plus / protobuf Message
                method = getattr(proto, "method_name", "")
            if method:
                methods.add(method)
    except PermissionDenied as e:
        raise PermissionError(
            f"Cloud Logging access denied for project {project}\n"
            f"  Missing permission: logging.logEntries.list\n"
            f"  Fix: grant the 'Logs Viewer' role to your caller identity\n"
            f"  GCP error: {e.message}"
        ) from e
    except GoogleAPICallError as e:
        raise RuntimeError(f"Cloud Logging error: {e.message}") from e

    return methods
