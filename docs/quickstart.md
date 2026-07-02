# Quickstart

Get iam-zero up and running in under 5 minutes.

## 1. Install

=== "pip"

    ```bash
    pip install zero-iam
    ```

=== "pipx"

    ```bash
    pipx install zero-iam
    ```

=== "Homebrew"

    ```bash
    brew tap MaripeddiSupraj/tap
    brew install iam-zero
    ```

## 2. Configure

```bash
iam-zero configure
```

This will prompt you for:

- **Anthropic API key** &mdash; required for Claude-powered analysis
- **GitHub personal access token** (optional) &mdash; needed only for `--github` mode
- **Default repo** (owner/repo) (optional) &mdash; needed only for `--github` mode

## 3. Enable Cloud APIs

=== "AWS"

    Ensure your caller identity has the following permissions:

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "cloudtrail:LookupEvents",
            "iam:GenerateServiceLastAccessedDetails",
            "iam:GetServiceLastAccessedDetails",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:ListRolePolicies",
            "iam:GetRolePolicy"
          ],
          "Resource": "*"
        }
      ]
    }
    ```

=== "GCP"

    ```bash
    gcloud services enable \
      cloudresourcemanager.googleapis.com \
      logging.googleapis.com \
      iam.googleapis.com \
      --project YOUR-PROJECT
    ```

    Your caller identity needs:
    - `resourcemanager.projects.getIamPolicy`
    - `logging.logEntries.list`

## 4. Scan a Role

=== "AWS"

    ```bash
    iam-zero scan aws --role arn:aws:iam::123456789012:role/my-role
    ```

=== "GCP"

    ```bash
    iam-zero scan gcp \
      --service-account sa@my-project.iam.gserviceaccount.com \
      --project my-project
    ```

That's it! The output will show findings in a clean terminal table.

!!! tip "Safe by default"
    All scans run in **dry-run mode** by default. Nothing is written or modified until you explicitly pass `--output` or `--github`.
