# Security Policy

iam-zero analyzes cloud authorization data and produces review artifacts. Treat
cloud credentials, IAM policies, audit logs, generated recommendations, GitHub
tokens, and model API keys as security-sensitive.

## Reporting a vulnerability

Please do not publish credentials, account IDs, private policy documents, or
exploit details in a public issue.

Use GitHub's private **Security → Report a vulnerability** flow when available.
If private vulnerability reporting is unavailable, open a minimal issue asking
for a private contact channel without including sensitive details.

A useful report includes the affected version/commit, cloud provider, a
sanitized reproduction, and the security impact.

## Safety model

- iam-zero never applies IAM changes directly.
- AWS removals require corroborating IAM last-accessed evidence by default.
- CloudTrail-only AWS mode is advisory.
- GCP audit-log heuristic mode is advisory.
- LLM output is advisory and cannot bypass deterministic safety guards.
