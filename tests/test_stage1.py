"""M2：Stage 1 過濾的解析 / 驗證 / 重試行為。

不打真實 LLM：monkeypatch chat() 與 get_settings()，專注測「拿到 LLM 原始輸出後
能否正確 strip 圍欄、抽 JSON、pydantic 驗證、失敗重試一次」。
"""

import json
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


# --- 成員 A 報告的 5 筆真實樣本（label = 正確答案 / 模型應輸出的目標）-------------
# 之後 M6 也會放進 data/self_made/。測試以「模型輸出目標 label」mock LLM，
# 驗證 Stage1Result 能正確驗證該輸出。
MEMBER_A_SAMPLES = [
    ("IT 部門通知：請於今日更新密碼，否則帳號停用", "suspicious"),
    ("下週一開會通知，請確認出席", "safe"),
    ("您的包裹配送失敗，請點擊連結重新安排", "suspicious"),
    ("財務部：請匯款至以下帳號完成核銷", "suspicious"),
    ("HR：本月薪資單已上傳至系統，請自行下載", "safe"),
]


@pytest.mark.parametrize("body,label", MEMBER_A_SAMPLES)
def test_member_a_samples_validate(monkeypatch, body, label):
    raw = json.dumps({"label": label, "reason": "依樣本預期判定"}, ensure_ascii=False)
    monkeypatch.setattr(stage1_filter, "chat", _fake_chat(raw))
    result = stage1_filter.run(_msg(body=body))
    assert isinstance(result, Stage1Result)
    assert result.label == label
    assert result.reason


def test_strips_json_fence(monkeypatch):
    raw = '```json\n{"label": "suspicious", "reason": "寄件者網域異常"}\n```'
    monkeypatch.setattr(stage1_filter, "chat", _fake_chat(raw))
    assert stage1_filter.run(_msg()).label == "suspicious"


def test_ignores_leading_prose(monkeypatch):
    raw = '好的，分析結果如下：{"label": "suspicious", "reason": "語氣緊迫要求個資"}'
    monkeypatch.setattr(stage1_filter, "chat", _fake_chat(raw))
    assert stage1_filter.run(_msg()).label == "suspicious"


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
    with pytest.raises(ValueError, match="共嘗試 2 次"):
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


@pytest.mark.parametrize(
    "raw_conf,expected",
    [("high","high"),("HIGH","high"),("Medium","medium"),("low","low"),("不確定","medium")],
)
def test_confidence_is_normalized(monkeypatch, raw_conf, expected):
    raw = json.dumps({"label":"suspicious","reason":"x","confidence":raw_conf}, ensure_ascii=False)
    monkeypatch.setattr(stage1_filter, "chat", _fake_chat(raw))
    assert stage1_filter.run(_msg()).confidence == expected

def test_confidence_defaults_to_medium_when_absent(monkeypatch):
    raw = json.dumps({"label":"safe","reason":"x"}, ensure_ascii=False)
    monkeypatch.setattr(stage1_filter, "chat", _fake_chat(raw))
    assert stage1_filter.run(_msg()).confidence == "medium"
