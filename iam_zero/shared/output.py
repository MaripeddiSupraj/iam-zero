from dataclasses import dataclass
import json
import os


@dataclass(frozen=True)
class OutputMode:
    is_dry_run: bool   # terminal only — no files written, no PRs opened
    file_path: str | None  # write policy JSON here (None = don't write)
    github: bool       # open GitHub PR


def resolve_output_mode(
    dry_run: bool,
    output: str | None,
    github: bool,
) -> OutputMode:
    """
    Derive the effective output mode from CLI flags.

    Priority rules (from CLAUDE.md):
    - --dry-run always wins: no files written, no PRs opened
    - No flags at all = dry-run (safe by default)
    - --output and --github are independent and can be combined
    """
    if dry_run or (not output and not github):
        return OutputMode(is_dry_run=True, file_path=None, github=False)
    return OutputMode(is_dry_run=False, file_path=output, github=github)


def write_policy_file(path: str, policy_json: str) -> None:
    """Write policy JSON to a file, creating parent directories as needed."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w") as f:
        f.write(policy_json)
        if not policy_json.endswith("\n"):
            f.write("\n")
