"""Stage 2：旗艦 LLM 意圖分析。

M3 實作。呼叫 MODEL_STAGE2 → 解析驗證為 Stage2Result →
用 mitre.validate_techniques() 過濾、必要時用 TACTIC_TO_TECHNIQUE 補正。
"""

# TODO(M3): run(msg) -> Stage2Result
