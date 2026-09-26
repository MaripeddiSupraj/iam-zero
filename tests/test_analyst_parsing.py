import pytest

from iam_zero.agent.analyst import (
    _complete_findings,
    _extract_json_array,
    _validate_findings,
)


def test_extracts_plain_array():
    raw = '[{"permission": "s3:PutObject", "recommendation": "remove", "risk": "low", "reason": "x"}]'
    assert _extract_json_array(raw)[0]["permission"] == "s3:PutObject"


def test_extracts_array_wrapped_in_prose_and_fences():
    raw = 'Here is my analysis:\n```json\n[{"permission": "a", "recommendation": "keep", "risk": "high", "reason": "y"}]\n```\nDone.'
    assert _extract_json_array(raw)[0]["permission"] == "a"


def test_raises_on_no_array():
    with pytest.raises(ValueError):
        _extract_json_array("I cannot help with that.")


def test_validate_normalizes_bad_values():
    items = [
        {"permission": "s3:GetObject", "recommendation": "REMOVE IT", "risk": "extreme"},
        {"no_permission_key": True},
    ]
    findings = _validate_findings(items)
    assert len(findings) == 1
    assert findings[0]["recommendation"] == "investigate"
    assert findings[0]["risk"] == "medium"


def test_complete_findings_fails_closed_on_model_omission():
    completed = _complete_findings(
        [{"permission": "s3:GetObject", "recommendation": "remove", "risk": "low"}],
        ["s3:GetObject", "s3:PutObject"],
    )

    by_permission = {item["permission"]: item for item in completed}
    assert by_permission["s3:GetObject"]["recommendation"] == "remove"
    assert by_permission["s3:PutObject"]["recommendation"] == "investigate"
    assert "kept for safety" in by_permission["s3:PutObject"]["reason"]


def test_complete_findings_discards_hallucinated_permissions():
    completed = _complete_findings(
        [
            {"permission": "iam:DeleteAccount", "recommendation": "remove", "risk": "low"},
            {"permission": "s3:GetObject", "recommendation": "keep", "risk": "low"},
        ],
        ["s3:GetObject"],
    )
    assert [item["permission"] for item in completed] == ["s3:GetObject"]


def test_protected_action_cannot_be_removed_or_omitted():
    completed = _complete_findings(
        [],
        ["s3:GetObject"],
        {"s3:GetObject": "2026-09-20T10:00:00+00:00"},
    )
    finding = completed[0]
    assert finding["recommendation"] == "investigate"
    assert finding["last_used"] == "2026-09-20T10:00:00+00:00"
