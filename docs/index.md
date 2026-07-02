# iam-zero ⚡

**Detect overpermissive IAM roles on AWS and GCP. Auto-generate least-privilege policies. Open PRs &mdash; not tickets.**

[![PyPI version](https://img.shields.io/pypi/v/zero-iam)](https://pypi.org/project/zero-iam/)
[![Python versions](https://img.shields.io/pypi/pyversions/zero-iam)](https://pypi.org/project/zero-iam/)
[![License](https://img.shields.io/github/license/MaripeddiSupraj/iam-zero)](https://github.com/MaripeddiSupraj/iam-zero/blob/main/LICENSE)

---

Most IAM roles are massively over-permissioned. Teams either handcraft policies (slow, error-prone) or attach `AdministratorAccess` and pray. Neither scales.

**iam-zero** reads your actual audit logs &mdash; CloudTrail for AWS, Cloud Audit Logs for GCP &mdash; figures out what permissions a role *actually* uses, and opens a GitHub PR with a tightened policy. A human reviews before anything changes.

No agents writing IAM policies directly. No surprises. Everything goes through code review.

---

## Why iam-zero?

| Problem | Solution |
|---------|----------|
| Over-permissioned roles | Scans actual usage &mdash; only keeps what's needed |
| Manual policy writing | Auto-generates least-privilege policies |
| No audit trail | Opens a GitHub PR with full before/after diff |
| Risky auto-apply | Human reviews every change before merge |

---

## Quick Install

```bash
pip install zero-iam
iam-zero configure
```

See the [Quickstart guide](quickstart.md) to start scanning roles in under 5 minutes.

---

## Supported Providers

- **AWS** &mdash; CloudTrail + IAM Access Advisor
- **GCP** &mdash; Cloud Audit Logs (Admin Activity + Data Access)

---

## How It Works

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

No guesswork. No assumptions. Based on real usage data.
