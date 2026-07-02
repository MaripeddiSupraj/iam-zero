# Installation

## pip (Recommended)

```bash
pip install zero-iam
```

Requires Python 3.11+.

## pipx

```bash
pipx install zero-iam
```

This installs iam-zero in an isolated environment and makes the `iam-zero` command globally available.

## Homebrew

```bash
brew tap MaripeddiSupraj/tap
brew install iam-zero
```

## From Source

```bash
git clone https://github.com/MaripeddiSupraj/iam-zero
cd iam-zero
pip install -e ".[dev]"
```

## Verify Installation

```bash
iam-zero --help
```

You should see the help output with available commands.
