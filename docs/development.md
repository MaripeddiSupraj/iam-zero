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

11 test files covering: CloudTrail parsing, IAM analysis, Access Advisor, GCP method service extraction, GCP IAM analysis, policy generation (AWS + GCP), Claude response parsing, output mode resolution, and report formatting.

Tests use mocks (`moto` for AWS, `pytest-mock` for GCP) &mdash; no real cloud credentials needed.

## Code Style

```bash
ruff check .
```

Line length: 100. Target Python: 3.11.

## Project Structure

```
iam-zero/
├── iam_zero/
│   ├── __init__.py               # Stderr filter (gRPC noise suppression)
│   ├── cli.py                    # Click CLI entrypoint (608 lines)
│   ├── aws/
│   │   ├── cloudtrail.py         # CloudTrail event fetching
│   │   ├── iam_analyzer.py       # IAM policy reading + unused computation
│   │   ├── access_advisor.py     # Access Advisor data-plane corroboration
│   │   └── policy_generator.py   # Minimal policy JSON generation
│   ├── gcp/
│   │   ├── audit_logs.py         # Cloud Audit Log fetching
│   │   ├── iam_analyzer.py       # GCP IAM binding analysis
│   │   └── policy_generator.py   # GCP binding recommendation generation
│   ├── shared/
│   │   ├── config.py             # Config load/save (TOML)
│   │   ├── output.py             # Output mode resolution
│   │   ├── pr.py                 # GitHub PR creation (idempotent)
│   │   └── report.py             # Rich terminal output (banner, tables, spinners)
│   └── agent/
│       └── analyst.py            # Claude analysis layer (claude-sonnet-4-20250514)
├── tests/                        # 11 test files
│   ├── test_aws_policy_generator.py
│   ├── test_analyst_parsing.py
│   ├── test_output_modes.py
│   ├── test_cloudtrail.py
│   ├── test_report.py
│   ├── test_gcp_analyzer.py
│   ├── test_gcp_method_service.py
│   ├── test_aws_analyzer.py
│   ├── test_gcp_policy_generator.py
│   └── test_access_advisor.py
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
