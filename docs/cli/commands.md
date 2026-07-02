# CLI Commands

## `iam-zero configure`

Prompts for:

- **Anthropic API key** &mdash; required for analysis
- **GitHub personal access token** &mdash; optional, only needed for `--github` mode
- **Default repo** (owner/repo) &mdash; optional, only needed for `--github` mode

```bash
iam-zero configure
```

## `iam-zero auth test`

Verifies your cloud credentials are working.

| Option | Description |
|--------|-------------|
| `--profile <name>` | AWS profile to test (optional) |
| `--project <id>` | GCP project to test (optional) |

If neither flag is passed, both AWS and GCP are tested.

```bash
# Test both providers
iam-zero auth test

# Test specific providers
iam-zero auth test --profile my-aws-profile
iam-zero auth test --project my-gcp-project
```

## `iam-zero scan aws`

Scan an AWS IAM role for over-permissive policies.

### Options

| Option | Description |
|--------|-------------|
| `--role <arn>` | IAM role ARN to scan |
| `--all-roles` | Scan every IAM role in the account |
| `--profile <name>` | AWS profile to use |
| `--region <region>` | CloudTrail region (default: session default region) |
| `--days <n>` | Lookback period in days (max: 90) |
| `--no-access-advisor` | Skip Access Advisor (not recommended) |

### Output flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Print findings only (default) |
| `--output <path>` | Write recommended policy to file |
| `--github` | Open a GitHub PR |

### Examples

```bash
# Dry run (default)
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role

# Save to file
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role --output ./policy.json

# Open PR
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role --github

# Scan all roles in a specific region
iam-zero scan aws --all-roles --region eu-west-2
```

## `iam-zero scan gcp`

Scan a GCP service account.

### Options

| Option | Description |
|--------|-------------|
| `--service-account <email>` | Service account email |
| `--all-service-accounts` | Scan every SA in the project |
| `--project <id>` | GCP project ID |
| `--key-file <path>` | Service account key file |
| `--days <n>` | Lookback period in days |

| `--project <id>` | GCP project ID (required) |

### Output flags

Same as AWS: `--dry-run`, `--output <path>`, `--github`

### Examples

```bash
# Dry run
iam-zero scan gcp \
  --service-account sa@project.iam.gserviceaccount.com \
  --project my-project

# Save to file
iam-zero scan gcp \
  --service-account sa@project.iam.gserviceaccount.com \
  --project my-project \
  --output ./sa-policy.json

# Open PR
iam-zero scan gcp \
  --service-account sa@project.iam.gserviceaccount.com \
  --project my-project \
  --github

# Scan all service accounts
iam-zero scan gcp --all-service-accounts --project my-project
```
