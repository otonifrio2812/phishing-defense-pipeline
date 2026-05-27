"""威脅狩獵：MITRE ATT&CK technique 對照與驗證（硬規則 1）。

讓 Stage 2 的 tactics 可被 hunt / 比對標準。technique ID 已對照 attack.mitre.org
（截至知識庫；團隊可再覆核）：T1566 系列為 Phishing，T1598 為偵察階段的
Phishing for Information，T1657 Financial Theft 對應 BEC 誘導匯款。
"""

from __future__ import annotations

# 釣魚相關 technique（ID -> 名稱）。
ATTACK_TECHNIQUES: dict[str, str] = {
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1598": "Phishing for Information",
    "T1657": "Financial Theft",  # BEC / 誘導匯款
}

# 中文 tactic（子字串）→ technique，供後處理補正模型輸出。
TACTIC_TO_TECHNIQUE: dict[str, str] = {
    "仿冒品牌": "T1566",
    "可疑網域": "T1566.002",
    "誘導點擊連結": "T1566.002",
    "惡意附件": "T1566.001",
    "誘導匯款": "T1657",
    "竊取憑證": "T1566.002",
}


def validate_techniques(ids: list[str]) -> list[str]:
    """只保留出現在 ATTACK_TECHNIQUES 中的合法 ID（過濾模型亂編的 ID）。"""
    return [i for i in ids if i in ATTACK_TECHNIQUES]


def enrich_techniques(model_ids: list[str], tactics: list[str]) -> list[str]:
    """合併「模型給的合法 ID」與「由 tactics 子字串補正出的 ID」，去重保序。

    補正規則：若某條 tactic 文字包含 TACTIC_TO_TECHNIQUE 的任一中文關鍵詞，
    就補上對應 technique。確保 tactics 盡量都附帶有效 ATT&CK ID（硬規則 1）。
    """
    out: list[str] = []
    for i in validate_techniques(model_ids):
        if i not in out:
            out.append(i)
    for tactic in tactics:
        for keyword, tid in TACTIC_TO_TECHNIQUE.items():
            if keyword in tactic and tid not in out:
                out.append(tid)
    return out
