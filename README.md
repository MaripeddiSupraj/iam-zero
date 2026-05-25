# iam-zero

Detect overpermissive IAM roles on AWS and GCP, then automatically open PRs with tightened least-privilege policies.

**How it works:** iam-zero reads your actual audit logs (CloudTrail / Cloud Audit Logs), figures out which permissions are really used, uses Claude to assess removal safety, and raises a PR — so humans review before anything changes.

---

## Quickstart

### Install

```bash
# Homebrew (coming soon)
brew tap MaripeddiSupraj/tap
brew install iam-zero

# PyPI
pip install iam-zero
```

### Configure

```bash
iam-zero configure
# prompts for: GitHub PAT, default repo, Anthropic API key
```

### AWS

```bash
# Scan a specific role and open a PR
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role --days 90

# Preview what the PR would say (no PR opened)
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role --dry-run

# Just print the analysis to the terminal
iam-zero report aws --role arn:aws:iam::123456789012:role/my-role
```

**Required AWS permissions for your caller identity:**
- `cloudtrail:LookupEvents`
- `iam:GetRole`
- `iam:ListAttachedRolePolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:ListRolePolicies`
- `iam:GetRolePolicy`

### GCP

```bash
# Authenticate first
gcloud auth application-default login

# Scan a service account and open a PR
iam-zero scan gcp \
  --service-account sa@my-project.iam.gserviceaccount.com \
  --project my-project \
  --days 90

# Preview (no PR)
iam-zero scan gcp \
  --service-account sa@my-project.iam.gserviceaccount.com \
  --project my-project \
  --dry-run

# Just print the analysis
iam-zero report gcp \
  --service-account sa@my-project.iam.gserviceaccount.com \
  --project my-project
```

**Required GCP permissions for your caller identity:**
- `logging.logEntries.list`
- `iam.roles.get`
- `resourcemanager.projects.getIamPolicy`

### Test credentials

```bash
iam-zero auth test --project my-gcp-project
```

---

## How it works (in detail)

1. **Fetch audit logs** — CloudTrail (AWS) or Cloud Audit Logs (GCP) for the last N days
2. **Fetch current policy** — attached IAM policies or role bindings
3. **Diff** — which permissions are granted but never used?
4. **Claude analysis** — for each unused permission, is it safe to remove? (considers DR, infrequent processes)
5. **Generate minimal policy** — only what's actually needed
6. **Open PR** — before/after diff, per-permission rationale, idempotent (won't duplicate if PR already open)

---

## Safety guarantees

- **Read-only** — iam-zero never touches your IAM policies directly
- **Dry run** — `--dry-run` on every scan command
- **Human in the loop** — everything goes through a PR review before any change

---

## Development

```bash
git clone https://github.com/MaripeddiSupraj/iam-zero
cd iam-zero
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## License

MIT
