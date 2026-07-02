# GCP

iam-zero scans GCP service accounts using Cloud Audit Logs.

## Authentication

Uses Application Default Credentials (ADC):

```bash
gcloud auth application-default login
```

The credentials must have `resourcemanager.projects.getIamPolicy` and `logging.logEntries.list` permissions on the target project.

## Required Permissions

Your caller identity needs:

| Permission | Why |
|------------|-----|
| `resourcemanager.projects.getIamPolicy` | Read current IAM bindings |
| `logging.logEntries.list` | Read Cloud Audit Logs |

## Required APIs

Enable these in your project:

```bash
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  logging.googleapis.com \
  iam.googleapis.com \
  --project YOUR-PROJECT
```

## How GCP Scanning Works

1. **List service accounts** (for `--all-service-accounts`) &mdash; uses `IAMClient().list_service_accounts()` with `projects/{project}` parent
2. **Fetch IAM bindings** &mdash; reads the project's IAM policy via `resourcemanager_v3.ProjectsClient().get_iam_policy()`, filters bindings where member matches `serviceAccount:{email}`
3. **Get Cloud Audit Logs** &mdash; retrieves Admin Activity and Data Access logs for the target SA with `page_size=1000`
4. **Extract method names** &mdash; parses `methodName` from `protoPayload`; handles both short form (`storage.buckets.list`) and fully-qualified protobuf form (`google.logging.v2.LoggingServiceV2.ListLogEntries`)
5. **Compute unused** &mdash; `compute_unused_roles()` extracts service prefixes from used method names, compares against role service prefixes; primitive roles (no dot, e.g. `roles/viewer`) are always flagged
6. **Analyze** &mdash; Claude determines safe-to-remove candidates
7. **Generate** &mdash; `generate_minimal_bindings()` produces recommended roles JSON

## Listing Service Accounts

Use `--all-service-accounts` to scan every SA in the project:

```bash
iam-zero scan gcp --all-service-accounts --project my-project
```

## Limitations

- **Data Access audit logs are disabled by default.** If they're off, read-heavy usage (GCS reads, BigQuery queries) is invisible.
- **Admin Activity logs are always on** and cover all `METHOD_NAME` metadata changes.
