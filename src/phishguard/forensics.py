"""數位鑑識：SHA-256 雜湊 + append-only 稽核日誌（硬規則 3 & 4）。

★ 關鍵順序（不可顛倒）★
    1. 先對「原始 body」算 SHA-256 —— 這是 chain of custody 的錨點，用來事後驗證原件完整性。
    2. 再對 body / sender / subject 等做 privacy.redact()。
    3. 存「遮蔽後」的內容 + 「原文」的 hash。
若顛倒（先 redact 再 hash），存進去的 hash 會是遮蔽版的 hash，無法和原件比對，
chain of custody 就驗不了原件 —— 因此 make_record() 一律先 hash 原文、後 redact。

log 內**只**存遮蔽版（無原始個人 PII）；攻擊者 IOC（urls）原樣保留（硬規則 5）。
audit.jsonl 為 append-only（'a' 模式，一行一筆，不覆寫既有行）。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .privacy import redact
from .schema import Message, Stage1Result, Stage2Result, Stage3Result

LOG_DIR = Path(__file__).resolve().parents[2] / "logs"
AUDIT_PATH = LOG_DIR / "audit.jsonl"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    """對文字內容算 SHA-256（UTF-8 編碼）。"""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def make_record(
    msg: Message,
    s1: Stage1Result,
    s2: Optional[Stage2Result] = None,
    s3: Optional[Stage3Result] = None,
) -> dict:
    """產生一筆鑑識紀錄。s2/s3 為 None 代表在 Stage 1 就停下（safe）。

    嚴格順序：先 hash 原文 body，再 redact 後存遮蔽版（見模組 docstring）。
    """
    # 步驟 1：先對「原始 body」算 hash（錨點，務必在 redact 之前）。
    body_sha256 = sha256_text(msg.body)
    now = _iso_now()

    # 步驟 2 & 3：redact 個人 PII 後存遮蔽版；urls 是 IOC，原樣保留。
    record: dict = {
        "case_id": msg.case_id,
        "ingested_at": now,
        "sha256": body_sha256,  # 原文 hash
        "channel": msg.channel.value,
        "redacted": True,
        "stopped_at": "stage1" if s2 is None else None,
        "message": {
            "sender": redact(msg.sender),
            "subject": redact(msg.subject),
            "body": redact(msg.body),  # 遮蔽版
            "urls": list(msg.urls),  # IOC，不遮蔽
            "received_at": msg.received_at,
        },
        "stage1": {"label": s1.label, "reason": redact(s1.reason)},
        "chain_of_custody": [
            {"stage": "ingest", "ts": now},
            {"stage": "stage1", "ts": now},
        ],
    }

    if s2 is not None:
        record["stage2"] = {
            "verdict": s2.verdict,
            "confidence": s2.confidence,
            "tactics": [redact(t) for t in s2.tactics],
            "attack_techniques": list(s2.attack_techniques),  # ATT&CK ID，不遮蔽
            "evidence": [redact(e) for e in s2.evidence],
            "summary": redact(s2.summary),
        }
        record["chain_of_custody"].append({"stage": "stage2", "ts": now})

    if s3 is not None:
        record["stage3"] = {"briefing_text": redact(s3.briefing_text)}
        record["chain_of_custody"].append({"stage": "stage3", "ts": now})

    return record


def append_audit(record: dict) -> Path:
    """append-only 寫入 logs/audit.jsonl（一行一筆，不覆寫既有行）。回傳檔案路徑。"""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open("a", encoding="utf-8") as f:  # 'a' = append-only
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return AUDIT_PATH
