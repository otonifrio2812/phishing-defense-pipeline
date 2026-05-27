"""評估核心：資料入站遮蔽、預測、計算 P/R/F1。

eval/evaluate.py 是薄 CLI 包裝，真正邏輯在此（好測試 / 模組化）。

入站遮蔽（硬規則 4 & 5）：把標註資料載入時，先對「內容欄位」(body / subject) 做
privacy.redact 遮蔽受害者 PII；sender 與 urls 保留——sender 是 pipeline 需要的輸入訊號、
phishing 情境下也是攻擊者 IOC，urls 更是 IOC 證據，皆不遮蔽。

預測：對每筆跑 pipeline，取 Stage 2 verdict；若在 Stage 1 就判 safe，視為 legitimate
（保守過濾通過 = 正常）。正類別為 "phishing"（資安關注 Recall）。
"""

from __future__ import annotations

import json
from pathlib import Path

from sklearn.metrics import classification_report, precision_recall_fscore_support

from . import pipeline
from .privacy import redact
from .schema import Message

POSITIVE_LABEL = "phishing"
TARGET_F1 = 0.85


def ingest_record(raw: dict) -> dict:
    """入站遮蔽：redact 內容欄位的受害者 PII，保留 sender / urls。"""
    out = dict(raw)
    if out.get("body") is not None:
        out["body"] = redact(out["body"])
    if out.get("subject") is not None:
        out["subject"] = redact(out["subject"])
    # sender 保留（輸入訊號 / 攻擊者 IOC）；urls 保留（IOC 證據）。
    return out


def load_dataset(path: str | Path) -> list[dict]:
    """讀 labeled.jsonl（每行一筆已含 gold label 的 Message 結構）。"""
    records: list[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def predict(record: dict) -> str:
    """對單筆跑 pipeline，回傳預測 verdict（phishing / legitimate）。

    Message 會忽略多餘的 'label' 欄位（pydantic 預設 extra=ignore）。
    """
    msg = Message.model_validate(record)
    result = pipeline.process(msg)
    if result.get("stopped_at") == "stage1":
        return "legitimate"  # Stage 1 判 safe → 視為 legitimate
    stage2 = result.get("stage2")
    return stage2["verdict"] if stage2 else "legitimate"


def score(dataset: list[dict]) -> dict:
    """跑完整資料集，回傳 precision / recall / f1 / 報告字串 / 預測明細。"""
    y_true = [r["label"] for r in dataset]
    y_pred = [predict(r) for r in dataset]
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, pos_label=POSITIVE_LABEL, average="binary", zero_division=0
    )
    report = classification_report(y_true, y_pred, zero_division=0)
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "report": report,
        "y_true": y_true,
        "y_pred": y_pred,
    }
