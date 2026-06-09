"""OpenAI 相容 client（指向 Glows.ai 端點）。

若 Glows.ai 端點非 OpenAI 相容，**僅需改本檔 adapter**，其餘程式不動（CLAUDE.md gotcha）。
client 為 lazy 建立：import 本模組不會連線、也不需要金鑰，只有實際呼叫 chat() 才會。

另提供輕量的「呼叫次數計數器」（reset/get），供評估時量測成本
（單一大模型 vs 三階段級聯）。計數器在 chat() 內累加，因此 mock 掉 chat() 的測試會自動略過。
"""

from __future__ import annotations

from functools import lru_cache

from openai import OpenAI

from .config import get_settings


@lru_cache(maxsize=1)
def _client() -> OpenAI:
    s = get_settings()
    return OpenAI(base_url=s.api_base, api_key=s.api_key)


# --- LLM 呼叫次數計數器（成本量測用） ----------------------------------------
# 每次 chat() 實際送出請求就 +1（含解析失敗後的重試），可作為「成本」代理指標。
_call_count = 0


def reset_call_count() -> None:
    """把計數器歸零。"""
    global _call_count
    _call_count = 0


def get_call_count() -> int:
    """讀取自上次歸零以來，chat() 實際被呼叫的次數。"""
    return _call_count


def chat(model: str, prompt: str, *, temperature: float = 0.0) -> str:
    """送單則 user prompt，回傳模型純文字內容。

    保守取向用 temperature=0.0 讓偵測結果可重現。回傳內容可能含 ```json 圍欄或
    多餘文字 —— 由各 stage 解析前自行 strip，再經 pydantic 驗證（勿在此信任輸出）。
    """
    global _call_count
    _call_count += 1  # 計入一次實際 LLM 呼叫（成本量測）
    resp = _client().chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
    )
    return resp.choices[0].message.content or ""
