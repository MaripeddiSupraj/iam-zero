# Security & Safety

iam-zero is designed with a **safety-first** philosophy.

## Core Guarantees

### Read-Only by Default

iam-zero **never modifies IAM policies directly**. It only:

1. **Reads** audit logs and current policies
2. **Analyzes** the data
3. **Outputs** recommendations (to terminal, file, or PR)

No IAM policy changes happen without a human reviewing a PR first.

### Dry Run Always Available

Every `scan` command supports `--dry-run` (it's the default). This prints what the changes would be without writing anything or opening any PR.

### Human-in-the-Loop

All changes go through a GitHub PR before anything is applied:

```
iam-zero (read-only scan)
    ↓
Recommendations generated
    ↓
GitHub PR opened
    ↓
Human reviews
    ↓
Human merges
    ↓
CI/CD applies the change
```

### Idempotent PRs

Running the same scan twice won't create duplicate PRs. iam-zero checks for existing PRs before opening new ones.

## Limitations

!!! warning "Important caveats"

    - **Data-plane calls are invisible to CloudTrail management events.** Use Access Advisor for service-level corroboration.
    - **CloudTrail lookup is per-region.** Scan all regions your role operates in.
    - **GCP Data Access logs are off by default.** Enable them for read-heavy usage visibility.
    - **CloudTrail retains 90 days max.** You can't look back further.

## Best Practices

1. **Always start with a dry run** &mdash; see what would change before making it real
2. **Test in staging first** &mdash; apply the recommended policy to a staging copy of the role
3. **Review every removal** &mdash; Claude is smart, but you know your infrastructure best
4. **Monitor after applying** &mdash; watch for access denied errors in the days after tightening
