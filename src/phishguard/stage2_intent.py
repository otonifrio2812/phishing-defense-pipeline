"""Stage 2：旗艦 LLM 深度意圖分析（BEC / 釣魚）。

流程：載入 prompts/stage2_intent.txt → 渲染 Message → 呼叫 MODEL_STAGE2 →
（共用 parsing）抽 JSON / 驗證為 Stage2Result，失敗重試一次 →
用 mitre 過濾模型給的 technique ID、並由 tactics 補正（硬規則 1）。
"""

from __future__ import annotations

from pathlib import Path

from . import mitre
from .config import get_settings
from .llm_client import chat
from .parsing import parse_with_retry, render_message
from .schema import Message, Stage2Result

_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "stage2_intent.txt"


def run(msg: Message, low_confidence: bool = False) -> Stage2Result:
    """對單封可疑郵件做 Stage 2 意圖分析，回傳已驗證且 MITRE 補正過的 Stage2Result。

    low_confidence：Stage 1 對該郵件初篩信心偏低時，啟用更保守策略（進度報告 5.2）。
    """
    # .replace（非 str.format）：prompt 含字面 JSON 大括號，不能當成格式佔位符。
    prompt = _PROMPT_PATH.read_text(encoding="utf-8").replace("{message}", render_message(msg))
    if low_confidence:
        prompt += (
            "\n\n【注意】初篩階段對本郵件的信心偏低，請採更保守的判斷策略："
            "提高警戒、對模糊跡象傾向判為 phishing，以免漏報。"
        )
    model = get_settings().model_stage2
    result = parse_with_retry(lambda: chat(model, prompt), Stage2Result)

    # 威脅狩獵：過濾模型亂編的 ID，並由 tactics 補正出有效 ATT&CK ID。
    techniques = mitre.enrich_techniques(result.attack_techniques, result.tactics)
    return result.model_copy(update={"attack_techniques": techniques})
