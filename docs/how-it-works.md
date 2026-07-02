# How It Works

iam-zero follows a simple 4-step pipeline:

## Step 1: Fetch Audit Logs

=== "AWS"

    Uses CloudTrail's paginated `LookupEvents` API to retrieve all management events for the target role over the lookback period. The role ARN is parsed to extract the role name, which is used as the `Username` lookup attribute.

    Also calls IAM Access Advisor (`GenerateServiceLastAccessedDetails`) with a 60-second polling timeout to corroborate findings with service-level last-used data. Any service with recent Access Advisor activity is **protected** from removal regardless of Claude's output.

=== "GCP"

    Uses Cloud Audit Logs to retrieve Admin Activity and Data Access audit logs for the target service account. Logs are filtered by the service account's email and a configurable timestamp range, with a page size of 1000 entries.

    The `methodName` from each log entry's `protoPayload` is extracted. Method names come in two forms — short (`storage.buckets.list`) or fully-qualified protobuf (`google.logging.v2.LoggingServiceV2.ListLogEntries`) — and are normalized to extract the service prefix.

## Step 2: Extract Used Permissions

Every API call made by the role is extracted into a unique set of action/method strings. This gives the *actual* usage profile &mdash; not what the policy says, but what was *really called*.

## Step 3: Compare Against Current Policy

=== "AWS"

    The tool reads both **managed** and **inline** policies attached to the role via `iam_analyzer.get_role_policies()`. Actions are extracted and sorted. Wildcards (`*`, `service:*`) are always flagged as unused.

    `compute_unused()` returns actions in the current policy not covered by the used set.

    If Access Advisor data is available, `protect_active_services()` splits unused actions into truly unused vs protected (those whose service namespace had recent authentication — indicative of data-plane usage invisible to CloudTrail).

=== "GCP"

    The tool reads the project's IAM policy via `resourcemanager_v3.ProjectsClient().get_iam_policy()` and filters bindings matching the service account email.

    `compute_unused_roles()` extracts service prefixes from used method names (e.g. `storage` from `storage.buckets.list`) and compares against role service prefixes. **Primitive roles** (like `roles/viewer`, `roles/editor`) that have no service prefix are always flagged.

## Step 4: Claude-Powered Analysis

Each unused permission or role is analyzed by Claude (`claude-sonnet-4-20250514`) to determine whether it's safe to remove. The model receives a structured prompt with the role identity, current permissions, used permissions, and unused permissions, and returns a JSON array of findings.

!!! important "Protected actions"
    For AWS, actions protected by Access Advisor data can **never** be marked as `remove`, regardless of Claude's output. This is enforced in code after the API response is parsed.

| Risk Level | Meaning | Action |
|------------|---------|--------|
| **Low** | Permission is clearly unused with no side effects | ✂ Remove |
| **Medium** | Could be needed for infrequent tasks | ⚠ Review first |
| **High** | Removing might break critical workflows | ✋ Keep |

### Output

=== "AWS"

    `generate_minimal_policy()` builds the output by:
    1. Keeping actions that are **used** OR marked **keep**/**investigate** by Claude
    2. Mapping each kept action to its `Resource` from the original policy statements (via wildcard/prefix matching)
    3. Grouping actions by their resource sets for a compact policy
    4. Adding a `Sid: "IamZeroReviewUnmappedActions"` statement for any kept actions not covered by original statements

=== "GCP"

    `generate_minimal_bindings()` produces a JSON output with:
    - The service account email
    - Recommended roles (current roles minus those Claude marked as `remove`)
    - Removed roles (for reference)
    - A note about applying via `gcloud projects set-iam-policy`

Based on your flags, iam-zero can deliver this output in three ways:
1. **Print findings to terminal** &mdash; default dry-run mode
2. **Write policy to file** &mdash; `--output policy.json`
3. **Open a GitHub PR** &mdash; `--github` with full before/after diff
