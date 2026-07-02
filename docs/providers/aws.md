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

1. **Fetch CloudTrail events** &mdash; retrieves management events for the target role over N days
2. **Get Access Advisor data** &mdash; corroborates with service-level last-used information
3. **Compare policies** &mdash; identifies permissions in the policy NOT seen in logs
4. **Analyze** &mdash; Claude determines safe-to-remove candidates
5. **Generate** &mdash; produces a minimal policy JSON

## Limitations

- **CloudTrail `LookupEvents` records management events only.** Data-plane calls (S3 `GetObject`, DynamoDB `GetItem`, etc.) never appear. Access Advisor helps fill this gap at the service level.
- **Lookup is per-region.** Use `--region` for each region the role operates in.
- **90-day max retention.** `--days` beyond 90 won't return more data.
