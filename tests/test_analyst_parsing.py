import pytest
from iam_zero.agent.analyst import _complete_findings, _extract_json_array, _validate_findings


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



def test_complete_findings_preserves_omitted_candidate():
    findings = [
        {
            "permission": "s3:PutObject",
            "recommendation": "remove",
            "risk": "low",
            "reason": "unused",
            "last_used": None,
        }
    ]

    result = _complete_findings(findings, ["s3:PutObject", "s3:DeleteObject"])
    by_permission = {f["permission"]: f for f in result}

    assert by_permission["s3:PutObject"]["recommendation"] == "remove"
    assert by_permission["s3:DeleteObject"]["recommendation"] == "investigate"
    assert by_permission["s3:DeleteObject"]["risk"] == "high"


def test_complete_findings_discards_hallucinated_permission():
    findings = [
        {
            "permission": "iam:DeleteRole",
            "recommendation": "remove",
            "risk": "low",
            "reason": "hallucinated",
            "last_used": None,
        }
    ]

    result = _complete_findings(findings, ["s3:GetObject"])

    assert [f["permission"] for f in result] == ["s3:GetObject"]
    assert result[0]["recommendation"] == "investigate"


def test_complete_findings_never_auto_removes_wildcard():
    findings = [
        {
            "permission": "s3:*",
            "recommendation": "remove",
            "risk": "low",
            "reason": "not seen",
            "last_used": None,
        }
    ]

    result = _complete_findings(findings, ["s3:*"])

    assert result[0]["recommendation"] == "investigate"
    assert result[0]["risk"] == "high"


def test_complete_findings_protected_evidence_wins():
    findings = [
        {
            "permission": "s3:GetObject",
            "recommendation": "remove",
            "risk": "low",
            "reason": "not seen",
            "last_used": None,
        }
    ]

    result = _complete_findings(
        findings,
        ["s3:GetObject"],
        protected={"s3:GetObject": "2026-09-01T10:00:00+00:00"},
    )

    assert result[0]["recommendation"] == "investigate"
    assert result[0]["last_used"] == "2026-09-01T10:00:00+00:00"


def test_advisory_only_downgrades_remove():
    findings = [
        {
            "permission": "roles/storage.objectViewer",
            "recommendation": "remove",
            "risk": "low",
            "reason": "no matching methods",
            "last_used": None,
        }
    ]

    result = _complete_findings(
        findings,
        ["roles/storage.objectViewer"],
        advisory_only=True,
    )

    assert result[0]["recommendation"] == "investigate"
    assert result[0]["risk"] == "high"
