# GitHub PR Setup

To use `--github` output mode, you need to configure GitHub access.

## 1. Create a GitHub Token

1. Go to [GitHub Settings > Developer settings > Personal access tokens > Fine-grained tokens](https://github.com/settings/tokens?type=beta)
2. Create a token with:
   - **Repository access**: Select the repo where you want PRs opened
   - **Permissions**: `Contents: Read and write`, `Pull requests: Read and write`

Or use a classic token with `repo` scope.

## 2. Configure the Token

=== "Via CLI"

    ```bash
    iam-zero configure
    ```

    Enter your token when prompted.

=== "Manual"

    Edit `~/.iam-zero/config.toml`:

    ```toml
    [github]
    token = "ghp_your_token_here"
    repo = "your-org/your-infra"
    ```

## 3. Scan with PR Output

```bash
iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role --github
```

## How PRs Work

When `--github` is used, iam-zero:

1. Creates a new branch in the configured repo
2. Commits the recommended policy as `iam-zero/aws/my-role.recommended-policy.json`
3. Opens a PR with the full before/after diff
4. Sets the PR title to `fix(iam): tighten permissions for my-role [aws]`

### Idempotency

iam-zero checks if a PR already exists for this identity before opening a new one. Running the same scan twice won't create duplicate PRs.

### PR Contents

Each PR includes:

- **Summary** &mdash; N unused permissions, M recommended for removal
- **Findings table** &mdash; Permission | Last Used | Recommendation | Risk
- **Policy diff** &mdash; full before/after in code blocks
- **Testing instructions**
