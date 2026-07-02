# How It Works

iam-zero follows a simple 4-step pipeline:

## Step 1: Fetch Audit Logs

=== "AWS"

    Uses CloudTrail's `LookupEvents` API to retrieve all management events for the target role over the last 90 days.

    Also calls IAM Access Advisor (`GenerateServiceLastAccessedDetails`) to corroborate findings with service-level last-used data.

=== "GCP"

    Uses Cloud Audit Logs to retrieve Admin Activity and (optionally) Data Access audit logs for the target service account.

    Logs are filtered by the service account's email to extract only relevant events.

## Step 2: Extract Used Permissions

Every API call made by the role is extracted into a unique set of permissions. This gives us the *actual* usage profile &mdash; not what the policy says, but what was *really called*.

## Step 3: Compare Against Current Policy

The tool compares:

- **Current permissions** &mdash; what the role *can* do (from attached policies)
- **Used permissions** &mdash; what the role *actually did* (from audit logs)
- **Unused permissions** &mdash; candidates for removal

## Step 4: Claude-Powered Analysis

Each unused permission is analyzed by Claude to determine whether it's safe to remove:

| Risk Level | Meaning | Action |
|------------|---------|--------|
| **Low** | Permission is clearly unused with no side effects | ✂ Remove |
| **Medium** | Could be needed for infrequent tasks | ⚠ Review first |
| **High** | Removing might break critical workflows | ✋ Keep |

Claude also considers:

- **Blast radius** &mdash; how many services would be affected
- **Last used timestamp** &mdash; longer unused = safer to remove
- **Context clues** &mdash; action names that suggest critical functionality

## Step 5: Output

Based on your flags, iam-zero can:

1. **Print findings to terminal** &mdash; default dry-run mode
2. **Write policy to file** &mdash; `--output policy.json`
3. **Open a GitHub PR** &mdash; `--github` with full before/after diff
