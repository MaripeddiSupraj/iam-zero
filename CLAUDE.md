# iam-zero — Claude Code Agent Instructions

## What is iam-zero?

An open-source agentic CLI (and soon SaaS) that detects overpermissive IAM roles across AWS and GCP, then automatically opens PRs with tightened least-privilege policies.

**Core value prop:** Most IAM roles are massively over-permissioned. iam-zero reads actual audit logs, figures out what permissions are *really* used, and generates a minimal policy — then raises a PR so humans review before anything changes.

---

## Project Status

- **AWS support:** Core CloudTrail → analysis → PR flow exists. Needs hardening and edge case handling.
- **GCP support:** NEW — to be built. Use Cloud Audit Logs (Admin Activity + Data Access logs) as the source.
- **SaaS layer:** FUTURE — web UI + Stripe billing on top of the CLI core. Don't build this yet.

**Current focus: Get AWS + GCP CLI working end-to-end, robustly.**

---

## Tech Stack

- **Language:** Python 3.11+
- **AI SDK:** Anthropic SDK directly — no LangChain, no CrewAI, no frameworks
- **Model:** claude-sonnet-4-20250514 (always use latest Sonnet)
- **AWS:** boto3 — CloudTrail, IAM
- **GCP:** google-cloud-logging, google-cloud-iam — Cloud Audit Logs, IAM
- **GitHub PRs:** PyGithub or gh CLI
- **Config:** TOML or YAML for user config file
- **Distribution:** Homebrew (same pattern as terrawatch)
- **Testing:** pytest

---

## Architecture

```
iam-zero/
├── iam_zero/
│   ├── __init__.py
│   ├── cli.py                  # Click CLI entrypoint
│   ├── aws/
│   │   ├── cloudtrail.py       # Fetch + parse CloudTrail events
│   │   ├── iam_analyzer.py     # Detect overpermissive roles
│   │   └── policy_generator.py # Generate least-privilege policy
│   ├── gcp/
│   │   ├── audit_logs.py       # Fetch + parse Cloud Audit Logs
│   │   ├── iam_analyzer.py     # Detect overpermissive service accounts
│   │   └── policy_generator.py # Generate least-privilege IAM bindings
│   ├── shared/
│   │   ├── pr.py               # GitHub PR creation (shared)
│   │   ├── report.py           # Terminal output + summary
│   │   └── config.py           # Config loading
│   └── agent/
│       └── analyst.py          # Claude-powered analysis layer
├── tests/
├── CLAUDE.md
├── pyproject.toml
└── README.md
```

---

## Core Logic Flow

### AWS
1. Authenticate via AWS profile or env vars (boto3 default chain)
2. Pull CloudTrail events for a given role ARN over N days (default: 90)
3. Extract all unique `eventName` + `eventSource` pairs the role actually called
4. Compare against the role's current attached policies
5. Identify permissions in policy NOT seen in CloudTrail = candidates for removal
6. Use Claude to reason about which removals are safe vs risky
7. Generate a new minimal policy JSON
8. Open a GitHub PR: old policy vs new policy, with explanation

### GCP
1. Authenticate via Application Default Credentials (ADC) or service account key
2. Pull Cloud Audit Logs for a given service account over N days (default: 90)
3. Extract all unique `methodName` pairs the service account actually called
4. Compare against current IAM role bindings
5. Identify roles/permissions not exercised = candidates for removal
6. Use Claude to reason about safety
7. Generate updated IAM binding recommendation
8. Open a GitHub PR with before/after IAM policy + explanation

---

## CLI Commands

```bash
# AWS
iam-zero scan aws --role arn:aws:iam::123456789:role/my-role --days 90
iam-zero scan aws --all-roles --profile my-aws-profile
iam-zero report aws --role arn:aws:iam::123456789:role/my-role   # no PR, just print

# GCP
iam-zero scan gcp --service-account sa@project.iam.gserviceaccount.com --project my-project --days 90
iam-zero scan gcp --all-service-accounts --project my-project
iam-zero report gcp --service-account sa@project.iam.gserviceaccount.com

# Config
iam-zero configure   # interactive setup (GitHub token, default org/repo, etc.)
iam-zero auth test   # verify AWS + GCP credentials work
```

---

## Claude Agent Usage (analyst.py)

Claude is used ONLY for the reasoning step — deciding which unused permissions are safe to remove vs which might have legitimate but infrequent uses. Do NOT use Claude for parsing, API calls, or boilerplate.

```python
# Example pattern
response = anthropic_client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=2048,
    messages=[{
        "role": "user",
        "content": f"""
You are an AWS IAM security analyst.

Role ARN: {role_arn}
Current permissions: {current_permissions}
Permissions actually used (last {days} days): {used_permissions}
Unused permissions: {unused_permissions}

For each unused permission, assess:
1. Is it safe to remove? (yes/no/maybe)
2. Why? (brief reasoning)
3. Risk if removed incorrectly? (low/medium/high)

Return JSON only. No prose.
"""
    }]
)
```

Always request JSON responses from Claude for structured data. Parse with `json.loads()`.

---

## Engineering Rules

- **No broad except clauses** — catch specific exceptions, log them clearly
- **No silent failures** — if CloudTrail returns nothing, tell the user why (permissions? time range? wrong region?)
- **Read-only by default** — NEVER modify IAM policies directly. Only generate recommendations + open PRs
- **Dry run always available** — every `scan` command supports `--dry-run` (prints what PR would say, no PR opened)
- **Idempotent PRs** — check if a PR for this role already exists before opening another
- **Minimal dependencies** — don't add a library if stdlib or boto3/google-cloud already covers it
- **Test with mocks** — never hit real AWS/GCP in unit tests. Use `moto` for AWS, `pytest-mock` for GCP

---

## Authentication

### AWS
- Use boto3 default credential chain — don't hardcode anything
- Support `--profile` flag for named AWS profiles
- Require minimum permissions: `cloudtrail:LookupEvents`, `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`

### GCP
- Use Application Default Credentials (ADC) — `gcloud auth application-default login`
- Support `--service-account-key` for JSON key file override
- Require minimum permissions: `logging.logEntries.list`, `iam.roles.get`, `resourcemanager.projects.getIamPolicy`

### GitHub
- PAT token stored in config file (`~/.iam-zero/config.toml`)
- Never hardcode tokens anywhere

---

## PR Format

PR title: `fix(iam): tighten permissions for {role_name} [{cloud}]`

PR body must include:
- Summary: N unused permissions identified, M recommended for removal
- Table: Permission | Last Used | Recommendation | Risk
- Full before/after policy diff (in code blocks)
- How to test the changes
- Link to iam-zero docs

---

## Error Messages

Be specific and actionable. Bad: `Error fetching logs`. Good:
```
❌ CloudTrail access denied for role arn:aws:iam::123:role/my-role
   Missing permission: cloudtrail:LookupEvents
   Fix: attach the IAMZeroReadOnly policy to your caller identity
   Docs: https://github.com/MaripeddiSupraj/iam-zero#required-permissions
```

---

## What NOT to Build Yet

- Web UI / dashboard
- Stripe billing / SaaS layer
- Slack notifications
- Multi-account org-level scanning
- Azure support

**Focus: AWS + GCP CLI, working end-to-end, with good error handling and tests.**

---

## Testing the Tool

Supraj has:
- An active AWS account — use real CloudTrail for integration testing
- An active GCP account — use real Cloud Audit Logs for integration testing
- GitHub account: MaripeddiSupraj

Run integration tests against real accounts only manually, never in CI.

---

## Distribution Target

Homebrew tap — same pattern as `terrawatch`:
```
brew tap MaripeddiSupraj/tap
brew install iam-zero
```

PyPI as secondary distribution method.

---

## Definition of Done (Phase 1)

- [ ] `iam-zero scan aws --role <arn>` runs end-to-end and opens a real PR
- [ ] `iam-zero scan gcp --service-account <sa> --project <proj>` runs end-to-end and opens a real PR
- [ ] `--dry-run` works for both
- [ ] Clear error messages for auth failures and missing permissions
- [ ] README with quickstart for both AWS and GCP
- [ ] Homebrew installable
