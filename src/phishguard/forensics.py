"""數位鑑識：SHA-256 雜湊 + append-only 稽核日誌。

M5 實作。硬規則 3：記錄 case_id / ISO8601 時戳 / 原文 SHA-256；
logs/audit.jsonl append-only，不可覆寫既有行。
"""

# TODO(M5): make_record(msg, s1, s2, s3) -> dict（含 chain_of_custody）。
# TODO(M5): append_audit(record) -> 一行一筆寫入 logs/audit.jsonl。
