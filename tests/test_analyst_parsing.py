import pytest
from iam_zero.agent.analyst import _extract_json_array, _validate_findings


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
