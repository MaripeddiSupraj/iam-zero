# Output Modes

iam-zero supports three output modes, designed for different workflows.

## Mode Priority

| Priority | Mode | Flag | Side Effects |
|----------|------|------|--------------|
| 1 (highest) | Dry run | `--dry-run` | None |
| 2 | File output | `--output <path>` | Writes a file |
| 3 | GitHub PR | `--github` | Opens a PR |

`--dry-run` always takes priority. If you pass `--dry-run --github`, only dry-run runs.

## Dry Run (Default)

Prints findings to the terminal with a clean table and summary.

```bash
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role
```

Output includes:

- **Opening banner** &mdash; provider, identity, mode
- **Progress steps** &mdash; live status of each phase
- **Findings table** &mdash; permission | last seen | risk | recommendation
- **Summary panel** &mdash; blast radius reduction, next steps

## File Output

Writes the recommended policy JSON to a file. You can then review and manually apply it.

```bash
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role --output ./my-role-policy.json
```

After writing, the tool shows the command to apply it:

```
✓ Policy written to:  ./my-role-policy.json

Review it, then apply:
  aws iam put-role-policy --role-name my-role --policy-name tightened-policy --policy-document file://my-role-policy.json
```

## GitHub PR Mode

Opens a GitHub PR with the full before/after policy diff.

```bash
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role --github
```

The PR includes:

- **Title:** `fix(iam): tighten permissions for my-role [aws]`
- **Summary:** N unused permissions identified, M recommended for removal
- **Table:** Permission | Last Used | Recommendation | Risk
- **Full before/after diff** in code blocks
- **Testing instructions**

!!! note "GitHub setup required"
    You need a GitHub token and a configured repo to use `--github`. Run `iam-zero configure` to set these up.

## Combining Modes

File output and GitHub PR can be combined:

```bash
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role --output ./policy.json --github
```

This writes the policy to a file AND opens a PR with the diff.
