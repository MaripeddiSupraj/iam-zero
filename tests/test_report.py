import pytest
from iam_zero.shared.report import _blast_radius, _next_steps


class TestBlastRadius:
    def test_all_removable(self):
        findings = [
            {"recommendation": "remove"},
            {"recommendation": "remove"},
        ]
        assert _blast_radius(findings, total=2) == 100

    def test_none_removable(self):
        findings = [
            {"recommendation": "keep"},
            {"recommendation": "investigate"},
        ]
        assert _blast_radius(findings, total=4) == 0

    def test_partial_removable(self):
        findings = [
            {"recommendation": "remove"},
            {"recommendation": "remove"},
            {"recommendation": "keep"},
            {"recommendation": "investigate"},
        ]
        # 2 removable / 10 total = 20%
        assert _blast_radius(findings, total=10) == 20

    def test_rounds_to_nearest_int(self):
        findings = [{"recommendation": "remove"}]
        # 1/3 = 33.33... → 33
        assert _blast_radius(findings, total=3) == 33

    def test_zero_total(self):
        assert _blast_radius([], total=0) == 0

    def test_case_insensitive(self):
        findings = [{"recommendation": "REMOVE"}, {"recommendation": "Remove"}]
        assert _blast_radius(findings, total=2) == 100

    def test_empty_findings_nonzero_total(self):
        assert _blast_radius([], total=5) == 0


class TestNextSteps:
    def test_github_mode_returns_empty(self):
        steps = _next_steps("gcp", "sa@p.iam.gserviceaccount.com", "my-proj",
                            is_dry_run=False, has_file=False, has_github=True)
        assert steps == []

    def test_dry_run_shows_both_steps(self):
        steps = _next_steps("gcp", "sa@p.iam.gserviceaccount.com", "my-proj",
                            is_dry_run=True, has_file=False, has_github=False)
        labels = [s[0].strip() for s in steps]
        cmds = [s[1] for s in steps]
        assert any("output" in c for c in cmds), "should suggest --output"
        assert any("github" in c for c in cmds), "should suggest --github"

    def test_file_mode_shows_github_only(self):
        steps = _next_steps("gcp", "sa@p.iam.gserviceaccount.com", "my-proj",
                            is_dry_run=False, has_file=True, has_github=False)
        assert len(steps) == 1
        assert "--github" in steps[0][1]
        assert "--output" not in steps[0][1]

    def test_gcp_command_includes_project(self):
        steps = _next_steps("gcp", "sa@p.iam.gserviceaccount.com", "my-proj",
                            is_dry_run=True, has_file=False, has_github=False)
        cmds = " ".join(s[1] for s in steps)
        assert "--project my-proj" in cmds
        assert "--service-account sa@p.iam.gserviceaccount.com" in cmds

    def test_aws_command_uses_role_flag(self):
        steps = _next_steps("aws", "arn:aws:iam::123:role/my-role", None,
                            is_dry_run=True, has_file=False, has_github=False)
        cmds = " ".join(s[1] for s in steps)
        assert "--role arn:aws:iam::123:role/my-role" in cmds
        assert "scan aws" in cmds

    def test_gcp_command_omits_project_when_none(self):
        steps = _next_steps("gcp", "sa@p.iam.gserviceaccount.com", None,
                            is_dry_run=True, has_file=False, has_github=False)
        cmds = " ".join(s[1] for s in steps)
        assert "--project" not in cmds

    def test_no_flags_same_as_dry_run(self):
        dry = _next_steps("aws", "arn:aws:iam::1:role/r", None,
                          is_dry_run=True, has_file=False, has_github=False)
        default = _next_steps("aws", "arn:aws:iam::1:role/r", None,
                              is_dry_run=False, has_file=False, has_github=False)
        assert dry == default
