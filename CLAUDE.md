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
- **Terminal UI:** rich — colours, tables, spinners, panels
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
8. Output based on flags: print to terminal (--dry-run default), write to file (--output), open GitHub PR (--github)

### GCP
1. Authenticate via Application Default Credentials (ADC) or service account key
2. Pull Cloud Audit Logs for a given service account over N days (default: 90)
3. Extract all unique `methodName` pairs the service account actually called
4. Compare against current IAM role bindings
5. Identify roles/permissions not exercised = candidates for removal
6. Use Claude to reason about safety
7. Generate updated IAM binding recommendation
8. Output based on flags: print to terminal (--dry-run default), write to file (--output), open GitHub PR (--github)

---

## Output Modes

**CRITICAL DESIGN DECISION: Never assume GitHub is available.**

Not every team uses GitHub for IaC. Some use GitLab, some Bitbucket, some don't version control IAM at all. The tool must work usefully even with zero Git configuration.

Three output modes supported in Phase 1:

| Mode | Flag | Requires | Behaviour |
|------|------|----------|-----------|
| Dry run | `--dry-run` | Nothing | Prints full findings + recommended policy to terminal. No files written, no PRs opened. Always safe. |
| File output | `--output <path>` | Nothing | Writes recommended policy JSON to a file. User decides what to do with it. |
| GitHub PR | `--github` | GitHub token + repo in config | Opens a PR to the configured repo with before/after policy diff. |

**Rules:**
- `--dry-run` takes priority over everything — if set, never open a PR or write files
- `--output` and `--github` can be used together (write file AND open PR)
- If `--github` is passed but no token/repo is configured → fail with a clear error, suggest `iam-zero configure`
- Default behaviour (no flags) = `--dry-run` — safe by default, never surprises the user

**NOT in Phase 1 (future):**
- `--gitlab` GitLab MR support
- `--apply` direct IAM policy update via API (too dangerous for now)
- `--bitbucket`

---

## CLI Commands

```bash
# AWS — dry run (default, always safe)
iam-zero scan aws --role arn:aws:iam::123456789:role/my-role
iam-zero scan aws --role arn:aws:iam::123456789:role/my-role --dry-run

# AWS — save recommended policy to file
iam-zero scan aws --role arn:aws:iam::123456789:role/my-role --output ./my-role-policy.json

# AWS — open GitHub PR (requires token + repo configured)
iam-zero scan aws --role arn:aws:iam::123456789:role/my-role --github

# AWS — file + PR together
iam-zero scan aws --role arn:aws:iam::123456789:role/my-role --output ./policy.json --github

# AWS — scan all roles
iam-zero scan aws --all-roles --profile my-aws-profile

# GCP — same output modes apply
iam-zero scan gcp --service-account sa@project.iam.gserviceaccount.com --project my-project
iam-zero scan gcp --service-account sa@project.iam.gserviceaccount.com --project my-project --output ./sa-policy.json
iam-zero scan gcp --service-account sa@project.iam.gserviceaccount.com --project my-project --github
iam-zero scan gcp --all-service-accounts --project my-project

# Config
iam-zero configure   # interactive setup (GitHub token, default org/repo, Anthropic key)
iam-zero auth test   # verify AWS + GCP credentials and required permissions
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

## Output Format (Rich Terminal UI)

**Library: `rich`** — add to dependencies. Handles colours, tables, spinners, panels. No other UI library needed.

### 1. Opening Banner (on scan start)

```
╭─────────────────────────────────────────────╮
│  iam-zero ⚡  IAM Least-Privilege Scanner   │
╰─────────────────────────────────────────────╯

  Provider   GCP
  Identity   my-sa@my-project.iam.gserviceaccount.com
  Project    my-project
  Lookback   90 days
  Mode       dry-run
```

### 2. Progress Steps (live spinner on active step)

```
  ✓ Connected to GCP (my-project)
  ✓ Fetched IAM bindings  [12 roles]
  ⣾ Reading Cloud Audit Logs...  [day 67/90]
  ✓ Audit log analysis done  [3,421 events]
  ⣾ Claude is reasoning about safe removals...
  ✓ Analysis complete
```

- Use `rich.progress` or `rich.spinner` for the active step
- Checkmark (✓) in green when done
- Spinner (⣾) in yellow on active step

### 3. Findings Table (main output)

```
  ┌─ Findings ────────────────────────────────────────────────────┐

  12 permissions found  │  3 used  │  9 unused  │  7 removable

  └───────────────────────────────────────────────────────────────┘

  Permission                  Last Seen     Risk      Recommendation
  ──────────────────────────────────────────────────────────────────
  storage.buckets.delete      Never         LOW     ✂  Remove
  compute.instances.delete    Never         MED     ⚠  Review first
  iam.serviceAccounts.delete  Never         HIGH    ✋ Keep (risky)
  run.services.delete         Never         LOW     ✂  Remove
  storage.objects.get         2h ago        —       ✓  Keep (active)
  storage.objects.create      4h ago        —       ✓  Keep (active)
  ──────────────────────────────────────────────────────────────────
```

**Colour rules:**
- HIGH risk → red text
- MED risk → yellow text
- LOW risk → green text
- Active (kept) → dim/grey
- ✂ Remove → green
- ⚠ Review → yellow
- ✋ Keep → red
- ✓ Keep active → dim

### 4. Summary Panel (bottom)

```
  ╭─ Summary ────────────────────────────────────────────────────╮
  │                                                              │
  │   7 permissions safe to remove                              │
  │   2 flagged for manual review                               │
  │   3 active — kept untouched                                 │
  │                                                             │
  │   Blast radius reduction:  58%                              │
  │                                                             │
  ╰──────────────────────────────────────────────────────────────╯

  Next steps:
    Save policy     iam-zero scan gcp --service-account <sa> --output policy.json
    Open GitHub PR  iam-zero scan gcp --service-account <sa> --github
```

**Blast radius reduction** = (removable permissions / total permissions) × 100. Show as percentage. Security teams love this metric.

**Next steps block** — always show at the bottom of dry-run output. Show the exact command the user needs to run next. If `--output` was used, show the `--github` command. If `--github` was used, show nothing (they're done).

### 5. File Written Confirmation

```
  ✓ Policy written to:  ./my-sa-policy.json

  Review it, then apply:
    gcloud projects set-iam-policy my-project ./my-sa-policy.json
```

Show the exact cloud CLI command to apply the policy. AWS version uses `aws iam put-role-policy`.

### 6. PR Opened Confirmation

```
  ✓ GitHub PR opened:
    fix(iam): tighten permissions for my-sa [gcp]
    https://github.com/your-org/your-infra/pull/142
```

### Error Format

All errors use this pattern — never a bare Python traceback:

```
  ❌ GCP authentication failed
     Could not find Application Default Credentials
     Fix: run  gcloud auth application-default login
     Docs: https://github.com/MaripeddiSupraj/iam-zero#gcp-auth
```

Red ❌, bold error title, plain explanation, actionable fix, docs link.

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

- [ ] `iam-zero scan aws --role <arn>` runs in dry-run mode (default) and prints findings cleanly
- [ ] `iam-zero scan aws --role <arn> --output policy.json` writes recommended policy to file
- [ ] `iam-zero scan aws --role <arn> --github` opens a real GitHub PR
- [ ] Same three output modes work for GCP service accounts
- [ ] `--dry-run` flag always takes priority, never opens PRs or writes files
- [ ] If `--github` passed but not configured → clear error with fix instructions
- [ ] Clear error messages for auth failures and missing permissions
- [ ] 17+ tests passing (unit tests with mocks, no real AWS/GCP calls in CI)
- [ ] README with quickstart for both AWS and GCP
- [ ] Homebrew installable