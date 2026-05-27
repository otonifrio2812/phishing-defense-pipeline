"""Stage 1：輕量 LLM 快速二元過濾 safe / suspicious（Recall 優先）。

流程：載入 prompts/stage1_filter.txt → 渲染 Message → 呼叫 MODEL_STAGE1 →
strip ```json 圍欄與多餘文字 → json 解析 → pydantic 驗證為 Stage1Result。
解析 / 驗證失敗時**重試一次**，再失敗才 raise（CLAUDE.md：絕不直接信任 LLM 輸出）。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import ValidationError

from .config import get_settings
from .llm_client import chat
from .schema import Message, Stage1Result

# prompt 用檔案管理（敏捷：prompt 也要版本控管）；每次讀取，讓編輯立即生效。
_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "stage1_filter.txt"

# 抓 ```json ... ``` 圍欄內容（gotcha：LLM 偶爾回傳含圍欄或多餘文字）。
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


def _render(msg: Message) -> str:
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


def _extract_json(raw: str) -> str:
    """從 LLM 原始輸出抽出 JSON 物件字串：先去圍欄，再取第一個 { 到最後一個 }。"""
    m = _FENCE_RE.search(raw)
    candidate = m.group(1) if m else raw
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("LLM 回傳中找不到 JSON 物件")
    return candidate[start : end + 1]


def run(msg: Message) -> Stage1Result:
    """對單封郵件做 Stage 1 過濾，回傳已驗證的 Stage1Result。"""
    prompt = _PROMPT_PATH.read_text(encoding="utf-8").replace("{message}", _render(msg))
    model = get_settings().model_stage1

    last_err: Exception | None = None
    for _ in range(2):  # 原始一次 + 重試一次
        raw = chat(model, prompt)
        try:
            return Stage1Result.model_validate(json.loads(_extract_json(raw)))
        except (ValueError, json.JSONDecodeError, ValidationError) as e:
            last_err = e
    raise ValueError(f"Stage 1 無法解析 / 驗證 LLM 輸出（已重試一次）：{last_err}")
