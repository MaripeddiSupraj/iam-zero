# GCP

iam-zero scans GCP service accounts using Cloud Audit Logs.

## Authentication

Uses Application Default Credentials (ADC):

```bash
gcloud auth application-default login
```

Or use a service account key file directly:

```bash
iam-zero scan gcp \
  --service-account sa@project.iam.gserviceaccount.com \
  --project my-project \
  --key-file ./service-account-key.json
```

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

1. **Fetch IAM bindings** &mdash; reads the project's IAM policy
2. **Get Cloud Audit Logs** &mdash; retrieves Admin Activity and Data Access logs for the target SA
3. **Compare** &mdash; identifies roles in the binding NOT exercised in logs
4. **Analyze** &mdash; Claude determines safe-to-remove candidates
5. **Generate** &mdash; produces updated IAM binding recommendations

## Limitations

- **Data Access audit logs are disabled by default.** If they're off, read-heavy usage (GCS reads, BigQuery queries) is invisible.
- **Admin Activity logs are always on** and cover all `METHOD_NAME` metadata changes.
