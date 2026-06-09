"""M4：Stage 3 員工警示生成。

不打真實 LLM：monkeypatch chat() 與 get_settings()。
"""

from types import SimpleNamespace

import pytest

from phishguard import stage3_briefing
from phishguard.schema import Stage2Result, Stage3Result


@pytest.fixture(autouse=True)
def _fake_settings(monkeypatch):
    monkeypatch.setattr(
        stage3_briefing, "get_settings", lambda: SimpleNamespace(model_stage3="stub-model")
    )


def _s2():
    return Stage2Result(
        verdict="phishing",
        confidence=92,
        tactics=["緊迫性", "仿冒品牌"],
        attack_techniques=["T1566.002"],
        evidence=["仿冒 Microsoft 365", "可疑外部連結"],
        summary="偽冒 M365 的憑證竊取釣魚。",
    )


# 模型應產出的成員 C 五段格式範例（測試走 pass-through，驗證格式被原樣保留）。
WELL_FORMED = (
    "【⚠️ 釣魚郵件警戒通知】\n"
    "🔍 這封郵件偽裝成 Microsoft 365，用緊迫話術誘你點連結。\n"
    "🎯 想竊取你的帳號密碼。\n"
    "✅ 1) 別點連結 2) 直接從官網登入 3) 通報資安。\n"
    "📚 1) 留意網域 2) 對緊迫語氣存疑。"
)


def test_passes_through_briefing_text(monkeypatch):
    monkeypatch.setattr(stage3_briefing, "chat", lambda model, prompt, **kw: WELL_FORMED)
    result = stage3_briefing.run(_s2())
    assert isinstance(result, Stage3Result)
    # 五段 emoji 標記原樣保留（未改變成員 C 輸出格式）
    for marker in ("【⚠️ 釣魚郵件警戒通知】", "🔍", "🎯", "✅", "📚"):
        assert marker in result.briefing_text


def test_stage2_json_is_injected_into_prompt(monkeypatch):
    seen = {}

    def _chat(model, prompt, **kw):
        seen["prompt"] = prompt
        return WELL_FORMED

    monkeypatch.setattr(stage3_briefing, "chat", _chat)
    stage3_briefing.run(_s2())
    p = seen["prompt"]
    assert "{stage2_json}" not in p  # 佔位符已替換
    assert "phishing" in p and "T1566.002" in p  # Stage2 內容（含 MITRE）已注入
    assert "M1017" in p and "User Training" in p


def test_strips_whitespace(monkeypatch):
    monkeypatch.setattr(stage3_briefing, "chat", lambda model, prompt, **kw: "\n\n  內容  \n")
    assert stage3_briefing.run(_s2()).briefing_text == "內容"


def test_empty_output_retries_then_raises(monkeypatch):
    calls = {"n": 0}

    def _chat(model, prompt, **kw):
        calls["n"] += 1
        return "   "  # 永遠空白

    monkeypatch.setattr(stage3_briefing, "chat", _chat)
    with pytest.raises(ValueError, match="已重試一次"):
        stage3_briefing.run(_s2())
    assert calls["n"] == 2  # 重試一次後才放棄


def test_empty_then_valid_retry_succeeds(monkeypatch):
    seq = iter(["", WELL_FORMED])
    monkeypatch.setattr(stage3_briefing, "chat", lambda model, prompt, **kw: next(seq))
    assert "🔍" in stage3_briefing.run(_s2()).briefing_text
