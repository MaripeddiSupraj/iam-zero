import json
import os
import pytest

from iam_zero.shared.output import resolve_output_mode, write_policy_file, OutputMode


# ---------------------------------------------------------------------------
# resolve_output_mode
# ---------------------------------------------------------------------------

class TestResolveOutputMode:
    def test_no_flags_is_dry_run(self):
        mode = resolve_output_mode(dry_run=False, output=None, github=False)
        assert mode.is_dry_run is True
        assert mode.file_path is None
        assert mode.github is False

    def test_explicit_dry_run_flag(self):
        mode = resolve_output_mode(dry_run=True, output=None, github=False)
        assert mode.is_dry_run is True

    def test_dry_run_overrides_output(self):
        mode = resolve_output_mode(dry_run=True, output="policy.json", github=False)
        assert mode.is_dry_run is True
        assert mode.file_path is None

    def test_dry_run_overrides_github(self):
        mode = resolve_output_mode(dry_run=True, output=None, github=True)
        assert mode.is_dry_run is True
        assert mode.github is False

    def test_dry_run_overrides_both(self):
        mode = resolve_output_mode(dry_run=True, output="policy.json", github=True)
        assert mode.is_dry_run is True
        assert mode.file_path is None
        assert mode.github is False

    def test_output_only(self):
        mode = resolve_output_mode(dry_run=False, output="out/policy.json", github=False)
        assert mode.is_dry_run is False
        assert mode.file_path == "out/policy.json"
        assert mode.github is False

    def test_github_only(self):
        mode = resolve_output_mode(dry_run=False, output=None, github=True)
        assert mode.is_dry_run is False
        assert mode.file_path is None
        assert mode.github is True

    def test_output_and_github_combined(self):
        mode = resolve_output_mode(dry_run=False, output="policy.json", github=True)
        assert mode.is_dry_run is False
        assert mode.file_path == "policy.json"
        assert mode.github is True

    def test_output_mode_is_immutable(self):
        mode = resolve_output_mode(dry_run=False, output="policy.json", github=True)
        with pytest.raises(Exception):
            mode.is_dry_run = True  # frozen dataclass


# ---------------------------------------------------------------------------
# write_policy_file
# ---------------------------------------------------------------------------

class TestWritePolicyFile:
    def test_writes_content(self, tmp_path):
        path = str(tmp_path / "policy.json")
        write_policy_file(path, '{"Version": "2012-10-17"}')
        assert open(path).read().strip() == '{"Version": "2012-10-17"}'

    def test_adds_trailing_newline(self, tmp_path):
        path = str(tmp_path / "policy.json")
        write_policy_file(path, '{"a": 1}')
        assert open(path).read().endswith("\n")

    def test_no_double_newline_if_already_present(self, tmp_path):
        path = str(tmp_path / "policy.json")
        write_policy_file(path, '{"a": 1}\n')
        assert open(path).read() == '{"a": 1}\n'

    def test_creates_parent_directories(self, tmp_path):
        path = str(tmp_path / "nested" / "dir" / "policy.json")
        write_policy_file(path, "{}")
        assert os.path.exists(path)

    def test_overwrites_existing_file(self, tmp_path):
        path = str(tmp_path / "policy.json")
        write_policy_file(path, '{"old": true}')
        write_policy_file(path, '{"new": true}')
        assert "new" in open(path).read()
        assert "old" not in open(path).read()
