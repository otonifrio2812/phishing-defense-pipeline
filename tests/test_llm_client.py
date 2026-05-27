"""M7：LLM client 薄包裝 —— 不連網，mock 掉底層 OpenAI client。"""

from types import SimpleNamespace

from phishguard import llm_client


def _fake_openai(captured):
    """回傳一個假的 OpenAI client，記錄 create() 收到的參數。"""

    def _create(**kwargs):
        captured.update(kwargs)
        msg = SimpleNamespace(content="回傳內容")
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])

    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=_create)))


def test_chat_passes_args_and_returns_content(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(llm_client, "_client", lambda: _fake_openai(captured))

    out = llm_client.chat("my-model", "嗨")

    assert out == "回傳內容"
    assert captured["model"] == "my-model"
    assert captured["temperature"] == 0.0  # 預設可重現
    assert captured["messages"] == [{"role": "user", "content": "嗨"}]


def test_chat_handles_none_content(monkeypatch):
    def _client():
        msg = SimpleNamespace(content=None)
        return SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=lambda **kw: SimpleNamespace(
                    choices=[SimpleNamespace(message=msg)]
                ))
            )
        )

    monkeypatch.setattr(llm_client, "_client", _client)
    assert llm_client.chat("m", "x") == ""  # None content → 空字串，不爆
