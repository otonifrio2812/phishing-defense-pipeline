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


def _base(**over):
    """Stage2Result 必要欄位的基底，供正規化測試覆寫 tactics/evidence。"""
    return {
        "verdict": "phishing",
        "confidence": 90,
        "tactics": ["緊迫性"],
        "attack_techniques": ["T1566.002"],
        "evidence": ["可疑連結"],
        "summary": "釣魚",
        **over,
    }


def test_stage2_normalizes_structured_evidence_and_tactics():
    """本地模型常把 tactics/evidence 回成物件陣列；驗證後應為乾淨的 list[str]。"""
    from phishguard import forensics, ioc
    from phishguard.schema import Message, Stage1Result, Stage3Result

    # (1) 純 dict 陣列（含 {type, value}）
    r1 = Stage2Result.model_validate(
        _base(
            evidence=[
                {"type": "sender-email", "value": "偽冒寄件者網域"},
                {"type": "link", "value": "可疑外部連結"},
            ],
            tactics=[{"type": "urgency", "value": "緊迫性話術"}],
        )
    )
    assert r1.evidence == ["偽冒寄件者網域", "可疑外部連結"]
    assert r1.tactics == ["緊迫性話術"]

    # (2) str 與 dict 混雜在同一個 list
    r2 = Stage2Result.model_validate(
        _base(
            evidence=["純字串證據", {"type": "link", "value": "連結證據"}],
            tactics=["權威性", {"value": "稀缺性"}],
        )
    )
    assert r2.evidence == ["純字串證據", "連結證據"]
    assert r2.tactics == ["權威性", "稀缺性"]

    # (3) dict 無 'value' 鍵的 fallback：description → name → str(整個 dict)
    r3 = Stage2Result.model_validate(
        _base(
            evidence=[
                {"description": "只有描述"},
                {"name": "只有名稱"},
                {"foo": "bar"},
            ]
        )
    )
    assert r3.evidence[:2] == ["只有描述", "只有名稱"]
    assert r3.evidence[2] == str({"foo": "bar"})

    # 非 list 也包成單元素 list
    r4 = Stage2Result.model_validate(_base(evidence="單一字串證據", tactics="單一手法"))
    assert r4.evidence == ["單一字串證據"]
    assert r4.tactics == ["單一手法"]

    # 全部項目皆為 str（契約成立）
    for r in (r1, r2, r3, r4):
        assert all(isinstance(x, str) for x in r.evidence)
        assert all(isinstance(x, str) for x in r.tactics)

    # 下游 forensics 契約不變：make_record 對 evidence 逐項 redact（需為 str）
    msg = Message(case_id="t", body="點此", sender="a@evil.com")
    record = forensics.make_record(
        msg, Stage1Result(label="suspicious", reason="x"), r1, Stage3Result(briefing_text="b")
    )
    assert all(isinstance(e, str) for e in record["stage2"]["evidence"])

    # 下游 STIX 契約不變：仍能正常產出 bundle
    bundle = ioc.to_stix_bundle(Message(case_id="t", body="x", urls=["http://evil.com"]), r1)
    assert bundle is not None


def test_low_confidence_adds_conservative_instruction(monkeypatch):
    seen = {}
    def _chat(model, prompt, **kw):
        seen["prompt"] = prompt
        return json.dumps(M365_PAYLOAD, ensure_ascii=False)
    monkeypatch.setattr(stage2_intent, "chat", _chat)
    stage2_intent.run(_msg(), low_confidence=True)
    assert "更保守" in seen["prompt"]

def test_normal_confidence_has_no_extra_instruction(monkeypatch):
    seen = {}
    def _chat(model, prompt, **kw):
        seen["prompt"] = prompt
        return json.dumps(M365_PAYLOAD, ensure_ascii=False)
    monkeypatch.setattr(stage2_intent, "chat", _chat)
    stage2_intent.run(_msg())
    assert "更保守" not in seen["prompt"]
