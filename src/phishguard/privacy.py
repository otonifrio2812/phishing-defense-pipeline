"""隱私設計：遮蔽收件人 / 個人 PII。

M1 實作。硬規則 4 & 5：只遮蔽受害者 PII（email / 身分證 / 卡號 / 電話），
**絕不**遮蔽攻擊者的 URL / 網域（那是 IOC、是證據）。
"""

# TODO(M1): redact(text: str) -> str
#   email -> [EMAIL]；台灣身分證 [A-Z][12]\d{8} -> [ID]；
#   卡號 13-16 連續數字 -> [CARD]；電話 -> [PHONE]。
#   只 redact body / sender；urls 原樣保留。
