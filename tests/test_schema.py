"""M1：pydantic 模型驗證行為。"""

import pytest
from pydantic import ValidationError

from phishguard.schema import (
    Channel,
    Message,
    Stage1Result,
    Stage2Result,
    Stage3Result,
)


def test_message_defaults_to_email_channel():
    msg = Message(case_id="case_01", body="hello")
    assert msg.channel == Channel.email
    assert msg.urls == []


def test_stage1_rejects_unknown_label():
    Stage1Result(label="safe", reason="ok")  # 合法
    with pytest.raises(ValidationError):
        Stage1Result(label="maybe", reason="x")  # 非 safe/suspicious


def test_stage2_confidence_bounds():
    Stage2Result(
        verdict="phishing",
        confidence=87,
        tactics=["緊迫性"],
        attack_techniques=["T1566.002"],
        evidence=["可疑連結"],
        summary="…",
    )
    with pytest.raises(ValidationError):
        Stage2Result(
            verdict="phishing",
            confidence=101,  # 超出 0–100
            tactics=[],
            evidence=[],
            summary="…",
        )


def test_stage2_attack_techniques_optional_defaults_empty():
    r = Stage2Result(
        verdict="legitimate", confidence=10, tactics=[], evidence=[], summary="…"
    )
    assert r.attack_techniques == []


def test_stage3_briefing_text_required():
    Stage3Result(briefing_text="⚠️ …")
    with pytest.raises(ValidationError):
        Stage3Result()
