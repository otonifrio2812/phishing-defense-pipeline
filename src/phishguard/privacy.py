"""隱私設計：遮蔽收件人 / 個人 PII。

硬規則 4 & 5：
  - 只遮蔽**受害者 / 個人** PII（email / 台灣身分證 / 卡號 / 電話），替換成 token。
  - **絕不**遮蔽攻擊者的 URL / 網域 —— 那是 IOC、是證據。

由於釣魚 URL 常嵌在 body 文字中，且 URL query 可能含長數字串（會被「卡號」regex 誤判），
redact() 會先把 URL 抽出保護、做完 PII 遮蔽後再原樣還原，確保證據完整。
"""

from __future__ import annotations

import re

# --- 攻擊者 IOC：先保護，不遮蔽 -------------------------------------------------
# 抓 http(s):// 與 www. 開頭的 URL，吃到空白或常見中/英文結尾標點為止。
_URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'）)】，。]+""", re.IGNORECASE)

# --- 受害者 / 個人 PII：要遮蔽 --------------------------------------------------
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# 台灣身分證：1 個大寫英文字母 + (1|2) + 8 位數字。
_TW_ID_RE = re.compile(r"\b[A-Z][12]\d{8}\b")
# 卡號：13–16 位連續數字（依藍圖規格只抓「連續」數字）。
_CARD_RE = re.compile(r"\b\d{13,16}\b")
# 台灣電話：0 開頭，含可選 - 或空白分隔（手機 09xx-xxx-xxx、市話 0x-xxxxxxxx 等）。
_PHONE_RE = re.compile(r"\b0\d{1,3}[-\s]?\d{3,4}[-\s]?\d{3,4}\b")

# 還原用的佔位符：刻意用底線+大寫+數字，確保不會被上面任一 PII regex 命中。
_URL_TOKEN = "__PHISHGUARD_URL_{}__"
_URL_TOKEN_RE = re.compile(r"__PHISHGUARD_URL_(\d+)__")


def redact(text: str) -> str:
    """遮蔽字串中的個人 PII，但保留所有 URL（攻擊者 IOC）原樣。

    遮蔽順序：email → 身分證 → 卡號 → 電話。URL 先抽出、最後還原。
    傳入 None / 空字串時原樣回傳。
    """
    if not text:
        return text

    # 1) 抽出並保護 URL。
    saved: list[str] = []

    def _stash(m: re.Match) -> str:
        saved.append(m.group(0))
        return _URL_TOKEN.format(len(saved) - 1)

    protected = _URL_RE.sub(_stash, text)

    # 2) 遮蔽 PII（順序重要：先 email，避免其中的數字被後續規則誤判）。
    protected = _EMAIL_RE.sub("[EMAIL]", protected)
    protected = _TW_ID_RE.sub("[ID]", protected)
    protected = _CARD_RE.sub("[CARD]", protected)
    protected = _PHONE_RE.sub("[PHONE]", protected)

    # 3) 還原 URL。
    return _URL_TOKEN_RE.sub(lambda m: saved[int(m.group(1))], protected)
