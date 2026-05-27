"""Stage 3：旗艦 LLM 把技術報告轉成員工可讀的白話警示。

流程：載入 prompts/stage3_briefing.txt → 注入 Stage2Result 的 JSON →
呼叫 MODEL_STAGE3 → 取回純文字警示，包成 Stage3Result。
（Stage 3 輸出是自由文字、非 JSON，故不走 parse_with_retry；空白才重試一次。）

ATT&CK 對齊（防禦面）：本階段產出的員工警示，對應緩解措施
**M1017 User Training（員工教育）**——見 mitre.STAGE3_MITIGATION。
Stage 2 標的是攻擊 technique，Stage 3 對應的是緩解 mitigation，
讓偵測與防禦兩端都能扣到 ATT&CK 標準。**本階段不改變成員 C 原 prompt 的輸出格式。**
"""

from __future__ import annotations

from pathlib import Path

from .config import get_settings
from .llm_client import chat
from .mitre import STAGE3_MITIGATION  # noqa: F401  ATT&CK 緩解對應：M1017 User Training
from .schema import Stage2Result, Stage3Result

_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "stage3_briefing.txt"


def run(s2: Stage2Result) -> Stage3Result:
    """把 Stage2Result 轉成員工可讀警示，回傳 Stage3Result。"""
    # .replace（非 str.format）：與其他 stage 一致，避免誤判大括號為佔位符。
    stage2_json = s2.model_dump_json(indent=2)
    prompt = _PROMPT_PATH.read_text(encoding="utf-8").replace("{stage2_json}", stage2_json)
    model = get_settings().model_stage3

    for _ in range(2):  # 原始一次 + 空白時重試一次
        text = chat(model, prompt).strip()
        if text:
            return Stage3Result(briefing_text=text)
    raise ValueError("Stage 3 產生空白警示（已重試一次）")
