"""M7：設定載入 —— 缺值報錯、齊全則回傳 Settings。"""

import pytest

from phishguard import config

_ENV = {
    "GLOWS_API_BASE": "https://example/v1",
    "GLOWS_API_KEY": "sk-test",
    "MODEL_STAGE1": "light",
    "MODEL_STAGE2": "flagship",
    "MODEL_STAGE3": "flagship",
}


@pytest.fixture(autouse=True)
def _clear_cache():
    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()


def test_get_settings_ok(monkeypatch):
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)
    s = config.get_settings()
    assert s.api_base == "https://example/v1"
    assert s.model_stage1 == "light"
    assert s.model_stage2 == "flagship"


def test_missing_vars_raise_with_names(monkeypatch):
    for k in _ENV:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(RuntimeError) as exc:
        config.get_settings()
    msg = str(exc.value)
    # 錯誤訊息應列出缺少的變數並指向 .env.example
    assert "GLOWS_API_BASE" in msg and ".env.example" in msg


def test_partial_missing_lists_only_missing(monkeypatch):
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("MODEL_STAGE2", raising=False)
    with pytest.raises(RuntimeError) as exc:
        config.get_settings()
    msg = str(exc.value)
    assert "MODEL_STAGE2" in msg
    assert "GLOWS_API_KEY" not in msg  # 已設定的不該被列為缺少
