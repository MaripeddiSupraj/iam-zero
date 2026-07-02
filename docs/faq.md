# FAQ

## General

### What is iam-zero?

iam-zero is a CLI tool that detects overpermissive IAM roles on AWS and GCP by reading actual audit logs, then generates least-privilege policies and opens GitHub PRs for review.

### Does it modify my IAM policies directly?

**No.** iam-zero is read-only by default. It generates recommendations that go through code review before any changes are applied.

### Which cloud providers are supported?

AWS (CloudTrail + IAM Access Advisor) and GCP (Cloud Audit Logs).

### What AI model does iam-zero use?

Claude Sonnet 4 (claude-sonnet-4-20250514) from Anthropic. Claude is used only for the reasoning step &mdash; deciding which unused permissions are safe to remove.

## Usage

### How do I get an Anthropic API key?

Sign up at [console.anthropic.com](https://console.anthropic.com) and create an API key.

### Can I use this without a GitHub account?

Yes. Use `--dry-run` (default) or `--output <file>` modes. `--github` is optional.

### What does dry-run mode do?

Prints findings to your terminal without writing any files or opening any PRs. Zero side effects.

### How far back does it look?

Up to 90 days (CloudTrail's retention limit). GCP Cloud Audit Logs can go further back depending on your retention settings.

## Security

### Is my data sent to Anthropic?

Only the list of permissions and role metadata are sent to Claude for analysis. No credentials, no policy content containing secrets, and no raw log data.

### Can iam-zero lock me out?

No &mdash; the tool generates _recommendations_. You choose whether to apply them. The default behavior is dry-run, which has zero side effects.

## Troubleshooting

### I get "CloudTrail access denied"

Your caller identity likely lacks one or more required IAM permissions. See the [AWS provider docs](providers/aws.md#required-permissions) for the full list.

### I get "GCP authentication failed"

Run `gcloud auth application-default login` to set up Application Default Credentials, or pass `--key-file` with a service account key path.

### The tool says "No events found" for my role

Possible reasons:
- The role hasn't made any API calls in the lookback period
- You're looking in the wrong CloudTrail region (use `--region`)
- CloudTrail isn't enabled in your account
- The role is very new
