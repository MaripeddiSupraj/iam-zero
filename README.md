# iam-zero ⚡

> Detect overpermissive IAM roles on AWS and GCP. Auto-generate least-privilege policies. Open PRs — not tickets.

Most IAM roles are massively over-permissioned. iam-zero reads your actual audit logs, figures out what permissions are *really* used, and opens a PR with a tightened policy — so a human reviews before anything changes.

---

## How it works

```text
CloudTrail / Cloud Audit Logs
        ↓
  What did this role actually call in the last 90 days?
        ↓
  Claude reasons: safe to remove vs. risky
        ↓
  Minimal policy generated
        ↓
  PR opened with before/after diff
```

No agents writing IAM policies directly. No surprises. Everything goes through code review.

---

## Install

```bash
pip install iam-zero
```

---

## Quickstart

### 1. Configure

```bash
iam-zero configure
# Prompts for Anthropic API key (required) + GitHub token (optional, for PRs)
```

### 2. Enable GCP APIs (one-time)

```bash
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  logging.googleapis.com \
  iam.googleapis.com \
  --project YOUR-PROJECT
```

### 3. Scan

```bash
# GCP — dry run (safe, no side effects)
iam-zero scan gcp \
  --service-account sa@my-project.iam.gserviceaccount.com \
  --project my-project

# AWS — dry run
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role
```

---

## Output modes

| Flag | What happens |
| ---- | ------------ |
| *(none)* | Dry run — findings printed to terminal, nothing written |
| `--dry-run` | Same, explicit |
| `--output policy.json` | Writes recommended policy to a file |
| `--github` | Opens a GitHub PR with full before/after diff |
| `--output policy.json --github` | Both |

`--dry-run` always takes priority. Safe by default.

---

## What the output looks like

```text
╭──────────────────────────────────────────────╮
│  iam-zero ⚡  IAM Least-Privilege Scanner    │
╰──────────────────────────────────────────────╯

  Provider    GCP
  Identity    terraform-review-sa@my-project.iam.gserviceaccount.com
  Project     my-project
  Lookback    90 days
  Mode        dry-run

  ✓  Fetching IAM role bindings  [4 roles]
  ✓  Reading Cloud Audit Logs    [1,204 unique methods]
  ✓  Claude analysis complete

  Permission                   Last Seen    Risk   Recommendation
  ───────────────────────────────────────────────────────────────
  roles/editor                 Never        HIGH   ✋ Keep (risky)
  roles/storage.objectAdmin    Never        LOW    ✂  Remove
  roles/logging.viewer         Never        LOW    ✂  Remove
  roles/iam.serviceAccountUser 3 days ago   —      ✓  Keep (active)

  ╭─ Summary ────────────────────────────────╮
  │  2 permissions safe to remove            │
  │  1 flagged for manual review             │
  │  1 active — kept untouched               │
  │                                          │
  │  Blast radius reduction:  50%            │
  ╰──────────────────────────────────────────╯
```

---

## Required permissions

### GCP (your caller identity)

- `resourcemanager.projects.getIamPolicy`
- `logging.logEntries.list`

### AWS (your caller identity)

- `cloudtrail:LookupEvents`
- `iam:GetRole`
- `iam:ListAttachedRolePolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:ListRolePolicies`
- `iam:GetRolePolicy`

---

## Safety

- **Read-only** — never modifies IAM policies directly
- **Dry run by default** — zero side effects unless you pass `--output` or `--github`
- **Human in the loop** — all changes go through a PR before anything is applied
- **Idempotent** — won't open a duplicate PR if one already exists for this identity

---

## Development

```bash
git clone https://github.com/MaripeddiSupraj/iam-zero
cd iam-zero
pip install -e ".[dev]"
pytest
```

---

## Roadmap

- [x] GCP service account scanning
- [x] AWS IAM role scanning
- [x] Claude-powered safe-removal analysis
- [x] GitHub PR output
- [ ] `--all-service-accounts` / `--all-roles` bulk scanning
- [ ] Homebrew install
- [ ] CI exit code for policy drift detection

---

## License

MIT
