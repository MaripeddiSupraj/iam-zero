# Development

## Setup

```bash
git clone https://github.com/MaripeddiSupraj/iam-zero
cd iam-zero
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

Tests use mocks (`moto` for AWS, `pytest-mock` for GCP) &mdash; no real cloud credentials needed.

## Code Style

```bash
ruff check .
```

## Project Structure

```
iam-zero/
├── iam_zero/
│   ├── __init__.py
│   ├── cli.py                    # Click CLI entrypoint
│   ├── aws/
│   │   ├── cloudtrail.py         # Fetch + parse CloudTrail events
│   │   ├── iam_analyzer.py       # Detect overpermissive roles
│   │   └── policy_generator.py   # Generate least-privilege policy
│   ├── gcp/
│   │   ├── audit_logs.py         # Fetch + parse Cloud Audit Logs
│   │   ├── iam_analyzer.py       # Detect overpermissive SAs
│   │   └── policy_generator.py   # Generate least-privilege bindings
│   ├── shared/
│   │   ├── pr.py                 # GitHub PR creation
│   │   ├── report.py             # Terminal output
│   │   └── config.py             # Config loading
│   └── agent/
│       └── analyst.py            # Claude analysis layer
├── tests/
├── docs/                         # MkDocs documentation
├── mkdocs.yml
├── pyproject.toml
└── README.md
```

## Building Docs

```bash
mkdocs build
```

To serve locally:

```bash
mkdocs serve
```
