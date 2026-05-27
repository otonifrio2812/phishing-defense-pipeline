"""Stage 1：輕量 LLM 快速二元過濾 safe / suspicious（Recall 優先）。

流程：載入 prompts/stage1_filter.txt → 渲染 Message → 呼叫 MODEL_STAGE1 →
（共用 parsing）strip 圍欄 / 抽 JSON / pydantic 驗證為 Stage1Result，失敗重試一次。
"""

from __future__ import annotations

from pathlib import Path

from .config import get_settings
from .llm_client import chat
from .parsing import parse_with_retry, render_message
from .schema import Message, Stage1Result

# prompt 用檔案管理（敏捷：prompt 也要版本控管）；每次讀取，讓編輯立即生效。
_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "stage1_filter.txt"


def run(msg: Message) -> Stage1Result:
    """對單封郵件做 Stage 1 過濾，回傳已驗證的 Stage1Result。"""
    # .replace（非 str.format）：prompt 含字面 JSON 大括號，不能當成格式佔位符。
    prompt = _PROMPT_PATH.read_text(encoding="utf-8").replace("{message}", render_message(msg))
    model = get_settings().model_stage1
    return parse_with_retry(lambda: chat(model, prompt), Stage1Result)
