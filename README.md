# iam-zero ⚡

> Detect overpermissive IAM access on AWS and GCP. Generate conservative least-privilege recommendations. Open PRs — not tickets.

[![PyPI version](https://img.shields.io/pypi/v/zero-iam)](https://pypi.org/project/zero-iam/)
[![Python versions](https://img.shields.io/pypi/pyversions/zero-iam)](https://pypi.org/project/zero-iam/)
[![CI](https://github.com/MaripeddiSupraj/iam-zero/actions/workflows/ci.yml/badge.svg)](https://github.com/MaripeddiSupraj/iam-zero/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/MaripeddiSupraj/iam-zero)](LICENSE)

Most IAM roles are massively over-permissioned. Teams either handcraft policies (slow, error-prone) or attach `AdministratorAccess` and pray. Neither scales.

iam-zero combines provider evidence with conservative analysis. On AWS it uses
CloudTrail plus IAM Access Advisor action-level and service-level last-accessed
data. On GCP it currently uses Cloud Audit Logs as an advisory signal.

The tool never applies IAM changes directly. AWS recommendations preserve the
original statement semantics (including conditions and explicit deny statements),
and every generated change still goes through human review. GCP findings are
advisory-only until a stronger provider-native signal is integrated.

---

## How it works

```
Provider evidence
  AWS: CloudTrail + IAM Access Advisor (ACTION_LEVEL)
  GCP: Cloud Audit Logs (advisory)
        ↓
  Deterministic candidate and safety guards
        ↓
  Claude explains risk / uncertainty
        ↓
  Conservative recommendation artifact
        ↓
  Optional GitHub PR for human review
```

---

## Quickstart

```bash
# 1. Install
pip install zero-iam

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
| `iam-zero scan aws --all-roles` | Scan every IAM role in the account |
| `iam-zero scan gcp --service-account <sa> --project <p>` | Single GCP service account (dry run) |
| `iam-zero scan gcp --all-service-accounts --project <p>` | Scan every SA in the project |
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
  roles/storage.objectAdmin    Never        LOW    ⚠  Investigate
  roles/logging.viewer         Never        LOW    ⚠  Investigate
  roles/iam.serviceAccountUser 3 days ago   —      ✓  Keep (active)

  ╭─ Summary ────────────────────────────────╮
  │  3 roles flagged for manual review       │
  │  1 active — kept untouched               │
  │                                          │
  │  GCP mode is advisory-only               │
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
- **Fail closed on incomplete model output** — omitted or hallucinated findings cannot silently remove access
- **AWS policy semantics preserved** — conditions, deny statements, resources, and other statement fields are retained
- **Access Advisor required by default on AWS** — use `--no-access-advisor` only when you explicitly accept reduced evidence
- **GCP advisory-only today** — heuristic findings are never converted into automatic role-removal recommendations
- **Human in the loop** — all changes go through review before anything is applied
- **Idempotent** — won't open a duplicate PR if one already exists for this identity
- **PRs carry the artifact** — the recommended policy is committed as
  `iam-zero/<cloud>/<identity>.recommended-policy.json` on the PR branch, so merging
  puts the policy in your repo for your IaC pipeline to pick up

---

## Known limitations (read before trusting output)

- **AWS evidence is still historical evidence, not proof of future need.** IAM Access
  Advisor is requested with action-level granularity and protects service-active
  permissions that do not have tracked action data, but infrequent disaster-recovery
  or seasonal permissions can still be legitimately unused during the observation window.
- **CloudTrail LookupEvents is supplementary.** It covers management events and is
  region-scoped; assumed-role sessions also make username-only lookup incomplete.
  iam-zero therefore does not rely on CloudTrail alone for AWS removal decisions.
- **Access Advisor action coverage is not universal.** AWS only reports action-level
  last-accessed information for tracked actions. Service-level activity is used as a
  conservative fallback.
- **GCP mode is advisory-only.** Data Access audit logs may be disabled and the current
  service-prefix heuristic is not permission-level proof. iam-zero will flag candidates
  for investigation but will not automatically recommend role removal in GCP mode.
- **Never treat a generated artifact as an apply-ready truth source.** Test changes in
  staging and review policy semantics and workload requirements before production rollout.

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
- [x] `--all-roles` / `--all-service-accounts` bulk scanning
- [ ] Homebrew install
- [ ] CI exit code for policy drift detection

---

## License

MIT
