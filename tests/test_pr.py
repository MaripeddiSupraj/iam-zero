from types import SimpleNamespace
from unittest.mock import MagicMock

from iam_zero.shared.pr import _find_existing_pr, _safe_branch_name, _safe_segment


def test_safe_segment_removes_path_and_ref_metacharacters():
    assert _safe_segment("../../prod role@x") == "prod-role-x"
    assert _safe_segment("...") == "identity"


def test_safe_branch_name_preserves_owned_prefix_without_unsafe_segments():
    assert _safe_branch_name("iam-zero/aws-prod/team role") == "iam-zero/aws-prod/team-role"


def test_find_existing_pr_matches_exact_title_not_prefix():
    repo = MagicMock()
    wrong = SimpleNamespace(
        title="fix(iam): tighten permissions for app-extra [aws]",
        head=SimpleNamespace(ref="iam-zero/aws-app-extra"),
    )
    right = SimpleNamespace(
        title="fix(iam): tighten permissions for app [aws]",
        head=SimpleNamespace(ref="renamed"),
    )
    repo.get_pulls.return_value = [wrong, right]

    assert (
        _find_existing_pr(
            repo,
            "fix(iam): tighten permissions for app [aws]",
            "iam-zero/aws-app",
        )
        is right
    )


def test_find_existing_pr_matches_owned_branch_after_manual_retitle():
    repo = MagicMock()
    pr = SimpleNamespace(
        title="human edited title",
        head=SimpleNamespace(ref="iam-zero/aws-app"),
    )
    repo.get_pulls.return_value = [pr]

    assert (
        _find_existing_pr(
            repo,
            "fix(iam): tighten permissions for app [aws]",
            "iam-zero/aws-app",
        )
        is pr
    )
