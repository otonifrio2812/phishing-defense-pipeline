"""評估核心：資料入站遮蔽、預測、計算 P/R/F1，以及「單一大模型 vs 三階段級聯」對照。

eval/evaluate.py 與 eval/compare.py 是薄 CLI 包裝，真正邏輯在此（好測試 / 模組化）。

入站遮蔽（硬規則 4 & 5）：把標註資料載入時，先對「內容欄位」(body / subject) 做
privacy.redact 遮蔽受害者 PII；sender 與 urls 保留——sender 是 pipeline 需要的輸入訊號、
phishing 情境下也是攻擊者 IOC，urls 更是 IOC 證據，皆不遮蔽。

預測：對每筆跑 pipeline，取 Stage 2 verdict；若在 Stage 1 就判 safe，視為 legitimate
（保守過濾通過 = 正常）。正類別為 "phishing"（資安關注 Recall）。

成本比較（handout 核心實驗）：在同一份資料集上比較兩種做法的準確率與「LLM 呼叫次數」。
旗艦模型呼叫是昂貴項；級聯只把 suspicious 案件送進旗艦，baseline 則每封都呼叫旗艦——
這就是「省成本」的來源。分類用原文（遮蔽僅作用於輸出，不影響判定）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel
from sklearn.metrics import classification_report, precision_recall_fscore_support

from . import llm_client, pipeline, stage1_filter, stage2_intent
from .config import get_settings
from .parsing import parse_with_retry, render_message
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


# ============================================================================
# 核心實驗：單一大模型 baseline vs 三階段級聯（準確率 + 成本）
# ============================================================================

# 單一大模型 baseline 的 prompt（實驗對照組；不分階段，一次旗艦呼叫判定整封郵件）。
_BASELINE_PROMPT = (
    "你是一位資深資安分析師，專門識別釣魚與商業電子郵件詐騙（BEC）。\n"
    "請判斷以下整封郵件是否為釣魚／社交工程郵件。\n"
    '只輸出 JSON，不要任何說明文字：{"verdict": "phishing" 或 "legitimate"}\n\n'
    "郵件內容：\n"
    "{message}\n"
)


class _BaselineResult(BaseModel):
    """baseline 只需要二元判定。"""

    verdict: Literal["phishing", "legitimate"]


def _prf(y_true: list[str], y_pred: list[str]) -> tuple[float, float, float]:
    """計算正類別（phishing）的 (precision, recall, f1)。"""
    p, r, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, pos_label=POSITIVE_LABEL, average="binary", zero_division=0
    )
    return float(p), float(r), float(f1)


def cascade_classify(msg: Message) -> tuple[str, int, int]:
    """三階段級聯的「分類路徑」：Stage 1 →（suspicious 才）Stage 2。

    回傳 (verdict, 輕量模型呼叫數, 旗艦模型呼叫數)。
    在每個 stage 前後 reset/讀取計數器，精準切出各階段呼叫數（含解析失敗重試），
    且不受兩階段是否用同一模型名影響。

    注意：此處刻意不跑 Stage 3（員工警示）——它不影響分類判定，且 baseline 無對應步驟，
    排除後成本比較才對等。
    """
    llm_client.reset_call_count()
    s1 = stage1_filter.run(msg)
    light_calls = llm_client.get_call_count()  # Stage 1 = 輕量模型

    if s1.label == "safe":
        return "legitimate", light_calls, 0  # 保守過濾通過 = 正常

    llm_client.reset_call_count()
    verdict = stage2_intent.run(msg).verdict
    flagship_calls = llm_client.get_call_count()  # Stage 2 = 旗艦模型
    return verdict, light_calls, flagship_calls


def baseline_classify(msg: Message) -> tuple[str, int]:
    """單一大模型 baseline：用一次旗艦模型呼叫直接判斷整封郵件。

    回傳 (verdict, 旗艦模型呼叫數)。
    """
    prompt = _BASELINE_PROMPT.replace("{message}", render_message(msg))
    model = get_settings().model_stage2  # 用旗艦模型（與級聯 Stage 2 同級，才公平）

    llm_client.reset_call_count()
    result = parse_with_retry(lambda: llm_client.chat(model, prompt), _BaselineResult)
    return result.verdict, llm_client.get_call_count()


def compare(dataset: list[dict]) -> dict:
    """在同一份資料集上比較「三階段級聯」與「單一大模型」的準確率與成本（LLM 呼叫數）。"""
    y_true = [r["label"] for r in dataset]
    cascade_pred: list[str] = []
    baseline_pred: list[str] = []
    casc_light = casc_flag = base_flag = 0

    for record in dataset:
        msg = Message.model_validate(record)  # 以原文分析（遮蔽僅用於輸出，不影響判定）
        v_c, n_light, n_flag = cascade_classify(msg)
        v_b, n_bflag = baseline_classify(msg)
        cascade_pred.append(v_c)
        baseline_pred.append(v_b)
        casc_light += n_light
        casc_flag += n_flag
        base_flag += n_bflag

    cp, cr, cf1 = _prf(y_true, cascade_pred)
    bp, br, bf1 = _prf(y_true, baseline_pred)

    return {
        "n": len(dataset),
        "cascade": {
            "precision": cp, "recall": cr, "f1": cf1,
            "light_calls": casc_light, "flagship_calls": casc_flag,
            "total_calls": casc_light + casc_flag,
        },
        "baseline": {
            "precision": bp, "recall": br, "f1": bf1,
            "light_calls": 0, "flagship_calls": base_flag,
            "total_calls": base_flag,
        },
    }


def format_comparison(result: dict) -> str:
    """把 compare() 結果排成可讀的對照表 + 成本摘要字串。"""
    c = result["cascade"]
    b = result["baseline"]
    n = result["n"]

    header = f"{'方法':<10}{'Precision':>11}{'Recall':>9}{'F1':>8}{'旗艦呼叫':>10}{'輕量呼叫':>10}{'總呼叫':>8}"
    row_base = (
        f"{'單一大模型':<8}{b['precision']:>11.3f}{b['recall']:>9.3f}{b['f1']:>8.3f}"
        f"{b['flagship_calls']:>10}{b['light_calls']:>10}{b['total_calls']:>8}"
    )
    row_casc = (
        f"{'三階段級聯':<8}{c['precision']:>11.3f}{c['recall']:>9.3f}{c['f1']:>8.3f}"
        f"{c['flagship_calls']:>10}{c['light_calls']:>10}{c['total_calls']:>8}"
    )
    lines = [f"資料集：{n} 封郵件", "", header, "-" * 66, row_base, row_casc, ""]

    saved = b["flagship_calls"] - c["flagship_calls"]
    if b["flagship_calls"] > 0:
        pct = saved / b["flagship_calls"] * 100
        lines.append(
            f"成本：級聯把昂貴的「旗艦模型呼叫」從 {b['flagship_calls']} 降到 "
            f"{c['flagship_calls']}（省 {saved} 次，約 {pct:.0f}%），"
            f"代價是多了 {c['light_calls']} 次輕量模型呼叫。"
        )
    return "\n".join(lines)
