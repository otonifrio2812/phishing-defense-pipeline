"""共用：Message 渲染、LLM JSON 抽取、以及「驗證 + 重試一次」。

stage1/2/3 共用，避免重複實作（敏捷 / 模組化）。
注意：prompt 檔內含字面 JSON 大括號（如 {"label": ...}），各 stage 一律用
`.replace("{message}", ...)` 注入內容，**不可** str.format()——否則 {} 會被當成佔位符。
"""

from __future__ import annotations

import json
import re
from typing import Callable, TypeVar

from pydantic import BaseModel, ValidationError

from .schema import Message

T = TypeVar("T", bound=BaseModel)

# 抓 ```json ... ``` 圍欄內容（gotcha：LLM 偶爾回傳含圍欄或多餘文字）。
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


def render_message(msg: Message) -> str:
    """把 Message 攤平成 prompt 可讀的文字區塊。"""
    parts: list[str] = []
    if msg.sender:
        parts.append(f"寄件者：{msg.sender}")
    if msg.subject:
        parts.append(f"主旨：{msg.subject}")
    parts.append(f"內文：{msg.body}")
    if msg.urls:
        parts.append("連結：" + ", ".join(msg.urls))
    return "\n".join(parts)


def extract_json(raw: str) -> str:
    """從 LLM 原始輸出抽出 JSON 物件字串：先去圍欄，再取第一個 { 到最後一個 }。"""
    m = _FENCE_RE.search(raw)
    candidate = m.group(1) if m else raw
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("LLM 回傳中找不到 JSON 物件")
    return candidate[start : end + 1]


def parse_with_retry(fetch: Callable[[], str], model_cls: type[T], *, attempts: int = 2) -> T:
    """呼叫 fetch() 取得 LLM 原始輸出 → 抽 JSON → pydantic 驗證為 model_cls。

    失敗時重試（共 attempts 次，預設 2 = 原始 + 重試一次），全數失敗才 raise。
    絕不直接信任 / eval LLM 輸出（CLAUDE.md）。
    """
    last_err: Exception | None = None
    for _ in range(attempts):
        raw = fetch()
        try:
            return model_cls.model_validate(json.loads(extract_json(raw)))
        except (ValueError, json.JSONDecodeError, ValidationError) as e:
            last_err = e
    raise ValueError(f"無法解析 / 驗證 LLM 輸出（共嘗試 {attempts} 次）：{last_err}")
