# Configuration

## Interactive Setup

The easiest way to configure iam-zero:

```bash
iam-zero configure
```

This prompts you for:

1. **Anthropic API Key** &mdash; get one from [console.anthropic.com](https://console.anthropic.com)
2. **GitHub Token** (optional) &mdash; classic PAT with `repo` scope from [GitHub Settings](https://github.com/settings/tokens)
3. **Default AWS Profile** (optional) &mdash; your AWS profile name
4. **Default GCP Project** (optional) &mdash; your GCP project ID

## Configuration File

Settings are stored in `~/.iam-zero/config.toml`:

```toml
[anthropic]
api_key = "sk-ant-..."

[github]
token = "ghp_..."
repo = "your-org/your-infra"

[aws]
profile = "default"

[gcp]
project = "my-project"
```

## Environment Variables

You can also use environment variables:

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `GITHUB_TOKEN` | GitHub PAT |
| `AWS_PROFILE` | AWS profile name |
| `GCP_PROJECT` | Default GCP project |

Environment variables take precedence over config file values.
