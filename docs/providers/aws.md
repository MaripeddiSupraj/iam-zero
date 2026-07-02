# AWS

iam-zero scans AWS IAM roles using CloudTrail management events and IAM Access Advisor.

## Authentication

Uses the standard boto3 credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. Shared credential file (`~/.aws/credentials`)
3. IAM role (EC2, ECS, EKS)

You can specify a profile with `--profile`:

```bash
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role --profile my-profile
```

## Required Permissions

Your caller identity needs:

| Permission | Why |
|------------|-----|
| `cloudtrail:LookupEvents` | Read CloudTrail events |
| `iam:GenerateServiceLastAccessedDetails` | Start Access Advisor analysis |
| `iam:GetServiceLastAccessedDetails` | Get Access Advisor results |
| `iam:GetRole` | Read role details |
| `iam:ListAttachedRolePolicies` | List managed policies |
| `iam:GetPolicy` | Read policy details |
| `iam:GetPolicyVersion` | Read policy content |
| `iam:ListRolePolicies` | List inline policies |
| `iam:GetRolePolicy` | Read inline policy content |

## How AWS Scanning Works

1. **Fetch CloudTrail events** &mdash; paginates `LookupEvents` by `Username` (extracted from role ARN) over N days
2. **Get IAM policies** &mdash; reads both managed and inline policies via `get_role_policies()`, extracts all allowed actions with wildcard expansion
3. **Access Advisor** &mdash; calls `GenerateServiceLastAccessedDetails` with 60s polling timeout, protects actions whose service had recent activity
4. **Compute unused** &mdash; `compute_unused()` returns actions in policy not in CloudTrail; wildcards always flagged; `protect_active_services()` splits protected vs truly unused
5. **Claude analysis** &mdash; sends current vs used vs unused to `claude-sonnet-4-20250514` for structured JSON assessment
6. **Generate policy** &mdash; `generate_minimal_policy()` keeps used + safe-to-keep actions, maps to original resources, adds `IamZeroReviewUnmappedActions` Sid for orphans

## Listing Roles

Use `--all-roles` to scan every IAM role in the account. Roles under the `/aws-service-role/` path are automatically skipped.

```bash
iam-zero scan aws --all-roles
```

## Limitations

- **CloudTrail `LookupEvents` records management events only.** Data-plane calls (S3 `GetObject`, DynamoDB `GetItem`, etc.) never appear. Access Advisor helps fill this gap at the service level.
- **Lookup is per-region.** Use `--region` for each region the role operates in.
- **90-day max retention.** `--days` beyond 90 won't return more data.
