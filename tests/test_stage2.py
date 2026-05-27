"""M3：Stage 2 意圖分析 + MITRE 補正。

不打真實 LLM：monkeypatch chat() 與 get_settings()。
"""

import json
from types import SimpleNamespace

import pytest

from phishguard import stage2_intent
from phishguard.schema import Message, Stage2Result


@pytest.fixture(autouse=True)
def _fake_settings(monkeypatch):
    monkeypatch.setattr(
        stage2_intent, "get_settings", lambda: SimpleNamespace(model_stage2="stub-model")
    )


def _patch_chat(monkeypatch, payload):
    raw = json.dumps(payload, ensure_ascii=False)
    monkeypatch.setattr(stage2_intent, "chat", lambda model, prompt, **kw: raw)


def _msg(body="您的 Microsoft 365 帳戶異常", **kw):
    return Message(case_id="t", body=body, **kw)


# 成員 B 的 Microsoft 365 釣魚樣本（代表性）：模型應判 phishing 並含有效 technique。
M365_PAYLOAD = {
    "verdict": "phishing",
    "confidence": 92,
    "tactics": ["緊迫性", "仿冒品牌", "誘導點擊連結"],
    "attack_techniques": ["T1566.002"],
    "evidence": ["仿冒 Microsoft 365 登入頁", "24 小時內停用的緊迫話術", "可疑外部驗證連結"],
    "summary": "偽冒 Microsoft 365 的憑證竊取釣魚。",
}


def test_m365_sample_phishing_with_valid_technique(monkeypatch):
    _patch_chat(monkeypatch, M365_PAYLOAD)
    result = stage2_intent.run(
        _msg(
            subject="您的 Microsoft 365 帳戶將於 24 小時內停用",
            urls=["http://m365-verify.example/login"],
        )
    )
    assert isinstance(result, Stage2Result)
    assert result.verdict == "phishing"
    assert "T1566.002" in result.attack_techniques  # 含有效 ATT&CK ID


def test_invalid_model_ids_are_filtered(monkeypatch):
    payload = {**M365_PAYLOAD, "attack_techniques": ["T9999", "T1566.002"], "tactics": []}
    _patch_chat(monkeypatch, payload)
    result = stage2_intent.run(_msg())
    assert result.attack_techniques == ["T1566.002"]  # 亂編的 T9999 被過濾


def test_techniques_augmented_from_tactics_when_model_gives_none(monkeypatch):
    payload = {**M365_PAYLOAD, "attack_techniques": [], "tactics": ["誘導匯款完成核銷"]}
    _patch_chat(monkeypatch, payload)
    result = stage2_intent.run(_msg())
    assert "T1657" in result.attack_techniques  # 由 tactic 補正


def test_fence_wrapped_output_validates(monkeypatch):
    raw = "```json\n" + json.dumps(M365_PAYLOAD, ensure_ascii=False) + "\n```"
    monkeypatch.setattr(stage2_intent, "chat", lambda model, prompt, **kw: raw)
    assert stage2_intent.run(_msg()).verdict == "phishing"


def test_confidence_out_of_range_is_rejected_then_retried(monkeypatch):
    bad = json.dumps({**M365_PAYLOAD, "confidence": 150}, ensure_ascii=False)
    good = json.dumps(M365_PAYLOAD, ensure_ascii=False)
    seq = iter([bad, good])
    monkeypatch.setattr(stage2_intent, "chat", lambda model, prompt, **kw: next(seq))
    result = stage2_intent.run(_msg())
    assert result.confidence == 92
