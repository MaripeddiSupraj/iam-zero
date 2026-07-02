# iam-zero ⚡

> Detect overpermissive IAM roles on AWS and GCP. Auto-generate least-privilege policies. Open PRs — not tickets.

[![PyPI version](https://img.shields.io/pypi/v/iam-zero)](https://pypi.org/project/iam-zero/)
[![Python versions](https://img.shields.io/pypi/pyversions/iam-zero)](https://pypi.org/project/iam-zero/)
[![License](https://img.shields.io/github/license/MaripeddiSupraj/iam-zero)](LICENSE)

Most IAM roles are massively over-permissioned. Teams either handcraft policies (slow, error-prone) or attach `AdministratorAccess` and pray. Neither scales.

iam-zero reads your actual audit logs — CloudTrail for AWS, Cloud Audit Logs for GCP — figures out what permissions a role *actually* uses, and opens a GitHub PR with a tightened policy. A human reviews before anything changes.

No agents writing IAM policies directly. No surprises. Everything goes through code review.

---

## How it works

```
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

---

## Quickstart

```bash
# 1. Install
pip install iam-zero

# 2. Configure (just your Anthropic key)
iam-zero configure

# 3. Enable GCP APIs (one-time, only if scanning GCP)
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  logging.googleapis.com \
  iam.googleapis.com \
  --project YOUR-PROJECT

# 4. Scan an AWS role — dry run by default, zero side effects
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role

# Or scan a GCP service account
iam-zero scan gcp \
  --service-account sa@my-project.iam.gserviceaccount.com \
  --project my-project
```

---

## Output modes

| Command | What happens |
| ------- | ------------ |
| `iam-zero scan aws --role <arn>` | **Dry run** — findings printed to terminal, nothing written |
| `iam-zero scan gcp --service-account <sa> --project <p>` | Same for GCP |
| `iam-zero scan aws --role <arn> --output policy.json` | Writes recommended policy to a file |
| `iam-zero scan aws --role <arn> --github` | Opens a GitHub PR with full before/after diff |
| `iam-zero scan aws --role <arn> --output policy.json --github` | Both file + PR |
| `iam-zero scan aws --role <arn> --region us-east-2` | Specify CloudTrail region (AWS only) |
| `iam-zero scan aws --role <arn> --no-access-advisor` | Skip Access Advisor corroboration (AWS only, not recommended) |

`--dry-run` always takes priority. **Safe by default.**

---

## What the output looks like

```
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

### AWS (your caller identity)

- `cloudtrail:LookupEvents`
- `iam:GenerateServiceLastAccessedDetails`
- `iam:GetServiceLastAccessedDetails`
- `iam:GetRole`
- `iam:ListAttachedRolePolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:ListRolePolicies`
- `iam:GetRolePolicy`

### GCP (your caller identity)

- `resourcemanager.projects.getIamPolicy`
- `logging.logEntries.list`

---

## Safety guarantees

- **Read-only** — never modifies IAM policies directly
- **Dry run by default** — zero side effects unless you pass `--output` or `--github`
- **Human in the loop** — all changes go through a PR before anything is applied
- **Idempotent** — won't open a duplicate PR if one already exists for this identity
- **PRs carry the artifact** — the recommended policy is committed as
  `iam-zero/<cloud>/<identity>.recommended-policy.json` on the PR branch, so merging
  puts the policy in your repo for your IaC pipeline to pick up

---

## Known limitations (read before trusting output)

- **CloudTrail `LookupEvents` records management events only.** Data-plane calls
  (`s3:GetObject`, `dynamodb:GetItem`, `sqs:SendMessage`, ...) never appear there.
  iam-zero corroborates with **IAM Access Advisor**: any action whose service shows
  recent authentication is automatically protected from a "remove" recommendation.
  Access Advisor is service-granular, not action-granular — treat every removal as
  a hypothesis and test in staging first.
- **CloudTrail lookup is per-region.** Pass `--region` for each region the role is
  active in, or activity outside your default region will be missed.
- **GCP Data Access audit logs are disabled by default.** If they're off, read-heavy
  usage (GCS reads, BigQuery queries) is invisible; iam-zero's prompt biases toward
  "investigate" for such roles, but enable Data Access logs for real signal.
- **CloudTrail `LookupEvents` retains 90 days.** `--days` beyond 90 won't return more.

---

## Development

```bash
git clone https://github.com/MaripeddiSupraj/iam-zero
cd iam-zero
pip install -e ".[dev]"
pytest      # 57 tests, all pass
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
