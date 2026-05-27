"""M2：Stage 1 過濾的解析 / 驗證 / 重試行為。

不打真實 LLM：monkeypatch chat() 與 get_settings()，專注測「拿到 LLM 原始輸出後
能否正確 strip 圍欄、抽 JSON、pydantic 驗證、失敗重試一次」。
"""

from types import SimpleNamespace

import pytest

from phishguard import stage1_filter
from phishguard.schema import Message, Stage1Result


@pytest.fixture(autouse=True)
def _fake_settings(monkeypatch):
    """避免測試需要 .env / 金鑰。"""
    monkeypatch.setattr(
        stage1_filter, "get_settings", lambda: SimpleNamespace(model_stage1="stub-model")
    )


def _fake_chat(*responses):
    """回傳一個依序吐出 responses 的假 chat()，並記錄被呼叫次數。"""
    calls = {"n": 0}

    def _chat(model, prompt, **kwargs):
        i = calls["n"]
        calls["n"] += 1
        return responses[min(i, len(responses) - 1)]

    _chat.calls = calls
    return _chat


def _msg(body="點此連結驗證您的帳戶", **kw):
    return Message(case_id="t", body=body, **kw)


# --- 成員 A 報告精神：5 筆代表性樣本，輸出皆能通過 Stage1Result 驗證 -------------
# 每筆模擬 LLM 對該情境會回傳的 raw 字串（含不同雜訊形式）。
FIVE_SAMPLES = [
    ('{"label": "safe", "reason": "內部例行通知，無可疑連結"}', "safe"),
    ('{"label": "suspicious", "reason": "要求點擊外部連結重設密碼"}', "suspicious"),
    ('```json\n{"label": "suspicious", "reason": "寄件者網域異常"}\n```', "suspicious"),
    ('好的，分析結果如下：{"label": "suspicious", "reason": "語氣緊迫要求個資"}', "suspicious"),
    ('```\n{"label": "safe", "reason": "純文字行銷信，無要求個資"}\n```', "safe"),
]


@pytest.mark.parametrize("raw,expected_label", FIVE_SAMPLES)
def test_five_samples_validate(monkeypatch, raw, expected_label):
    monkeypatch.setattr(stage1_filter, "chat", _fake_chat(raw))
    result = stage1_filter.run(_msg())
    assert isinstance(result, Stage1Result)
    assert result.label == expected_label
    assert result.reason


def test_renders_sender_subject_urls_into_prompt(monkeypatch):
    seen = {}

    def _chat(model, prompt, **kw):
        seen["prompt"] = prompt
        return '{"label": "suspicious", "reason": "x"}'

    monkeypatch.setattr(stage1_filter, "chat", _chat)
    stage1_filter.run(
        _msg(sender="ceo@evil.com", subject="緊急匯款", urls=["http://evil.com/pay"])
    )
    p = seen["prompt"]
    assert "ceo@evil.com" in p and "緊急匯款" in p and "http://evil.com/pay" in p
    # 佔位符已被替換，JSON 範例的字面大括號未被破壞
    assert "{message}" not in p
    assert '{"label"' in p


def test_retry_once_then_succeeds(monkeypatch):
    fake = _fake_chat("這不是 JSON", '{"label": "safe", "reason": "第二次才正確"}')
    monkeypatch.setattr(stage1_filter, "chat", fake)
    result = stage1_filter.run(_msg())
    assert result.label == "safe"
    assert fake.calls["n"] == 2  # 重試了一次


def test_raises_after_two_failures(monkeypatch):
    fake = _fake_chat("壞輸出", "還是壞輸出")
    monkeypatch.setattr(stage1_filter, "chat", fake)
    with pytest.raises(ValueError, match="已重試一次"):
        stage1_filter.run(_msg())
    assert fake.calls["n"] == 2  # 只重試一次，不無限重試


def test_invalid_label_is_rejected_then_retried(monkeypatch):
    # 第一次給 schema 不接受的 label，第二次給合法值 → 應重試後成功。
    fake = _fake_chat(
        '{"label": "maybe", "reason": "x"}', '{"label": "suspicious", "reason": "ok"}'
    )
    monkeypatch.setattr(stage1_filter, "chat", fake)
    assert stage1_filter.run(_msg()).label == "suspicious"
    assert fake.calls["n"] == 2
