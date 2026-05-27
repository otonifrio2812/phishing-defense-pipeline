"""Stage 1：輕量 LLM 快速二元過濾 safe / suspicious。

M2 實作。載入 prompts/stage1_filter.txt → 呼叫 MODEL_STAGE1 → 解析驗證為 Stage1Result。
JSON 解析失敗重試一次再 raise。
"""

# TODO(M2): run(msg) -> Stage1Result
