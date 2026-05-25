import os
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import tomli_w

CONFIG_DIR = Path.home() / ".iam-zero"
CONFIG_FILE = CONFIG_DIR / "config.toml"

_DEFAULTS: dict[str, Any] = {
    "github": {"token": "", "default_repo": ""},
    "aws": {"default_days": 90},
    "gcp": {"default_days": 90},
    "anthropic": {"api_key": ""},
}


def load_config() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        return _DEFAULTS.copy()
    with CONFIG_FILE.open("rb") as f:
        data = tomllib.load(f)
    merged = _DEFAULTS.copy()
    for section, values in data.items():
        if isinstance(values, dict):
            merged.setdefault(section, {})
            merged[section].update(values)
        else:
            merged[section] = values
    return merged


def save_config(cfg: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_FILE.open("wb") as f:
        tomli_w.dump(cfg, f)
    CONFIG_FILE.chmod(0o600)


def get_github_token(cfg: dict[str, Any]) -> str:
    token = os.environ.get("GITHUB_TOKEN") or cfg.get("github", {}).get("token", "")
    if not token:
        raise ValueError(
            "GitHub token not configured.\n"
            "  Run: iam-zero configure\n"
            "  Or set: export GITHUB_TOKEN=<your-token>"
        )
    return token


def get_anthropic_api_key(cfg: dict[str, Any]) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY") or cfg.get("anthropic", {}).get("api_key", "")
    if not key:
        raise ValueError(
            "Anthropic API key not configured.\n"
            "  Run: iam-zero configure\n"
            "  Or set: export ANTHROPIC_API_KEY=<your-key>"
        )
    return key
