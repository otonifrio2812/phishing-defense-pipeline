"""M6：評估框架 —— 入站遮蔽、預測、P/R/F1（全程 mock，不打真實 LLM）。"""

import json

import pytest

from phishguard import evaluation, forensics, ioc, pipeline
from phishguard.schema import Stage1Result, Stage2Result, Stage3Result


@pytest.fixture(autouse=True)
def _redirect_outputs(monkeypatch, tmp_path):
    """predict() 會跑 pipeline → 寫鑑識 / STIX；導到暫存目錄避免污染專案。"""
    monkeypatch.setattr(forensics, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(forensics, "AUDIT_PATH", tmp_path / "logs" / "audit.jsonl")
    monkeypatch.setattr(ioc, "REPORTS_DIR", tmp_path / "reports")


# --- 入站遮蔽 -------------------------------------------------------------------
def test_ingest_redacts_body_pii_but_keeps_url_and_sender():
    raw = {
        "case_id": "x",
        "channel": "email",
        "sender": "attacker@evil.com",
        "subject": "您好 victim@example.com",
        "body": "親愛的 victim@example.com，請點 http://evil.com/login?id=1234567890123456",
        "urls": ["http://evil.com/login?id=1234567890123456"],
        "label": "phishing",
    }
    out = evaluation.ingest_record(raw)
    # 受害者 PII（內容欄位的 email）被遮蔽
    assert "victim@example.com" not in out["body"]
    assert "victim@example.com" not in out["subject"]
    assert "[EMAIL]" in out["body"]
    # 攻擊者 URL（含長數字）保留於 body
    assert "http://evil.com/login?id=1234567890123456" in out["body"]
    # sender 與 urls 原樣保留（輸入訊號 / IOC）
    assert out["sender"] == "attacker@evil.com"
    assert out["urls"] == ["http://evil.com/login?id=1234567890123456"]


# --- predict -------------------------------------------------------------------
def _stub(monkeypatch, label, verdict=None):
    monkeypatch.setattr(pipeline.stage1_filter, "run", lambda msg: Stage1Result(label=label, reason="x"))
    if verdict is not None:
        monkeypatch.setattr(
            pipeline.stage2_intent,
            "run",
            lambda msg: Stage2Result(
                verdict=verdict, confidence=80, tactics=[], attack_techniques=[], evidence=[], summary="s"
            ),
        )
        monkeypatch.setattr(pipeline.stage3_briefing, "run", lambda s2: Stage3Result(briefing_text="b"))


def test_predict_safe_is_legitimate(monkeypatch):
    _stub(monkeypatch, "safe")
    assert evaluation.predict({"case_id": "c", "body": "開會通知"}) == "legitimate"


def test_predict_uses_stage2_verdict(monkeypatch):
    _stub(monkeypatch, "suspicious", verdict="phishing")
    assert evaluation.predict({"case_id": "c", "body": "點此驗證"}) == "phishing"


# --- score（用 case_id 路由，做出可控的混淆矩陣）-------------------------------
def _route_by_case(monkeypatch, verdict_by_case):
    monkeypatch.setattr(pipeline.stage1_filter, "run", lambda msg: Stage1Result(label="suspicious", reason="x"))
    monkeypatch.setattr(
        pipeline.stage2_intent,
        "run",
        lambda msg: Stage2Result(
            verdict=verdict_by_case[msg.case_id], confidence=80, tactics=[], attack_techniques=[], evidence=[], summary="s"
        ),
    )
    monkeypatch.setattr(pipeline.stage3_briefing, "run", lambda s2: Stage3Result(briefing_text="b"))


def test_score_perfect_predictions(monkeypatch):
    dataset = [
        {"case_id": "a", "body": "釣魚", "label": "phishing"},
        {"case_id": "b", "body": "正常", "label": "legitimate"},
    ]
    _route_by_case(monkeypatch, {"a": "phishing", "b": "legitimate"})
    result = evaluation.score(dataset)
    assert result["f1"] == 1.0
    assert result["precision"] == 1.0 and result["recall"] == 1.0
    assert result["y_pred"] == ["phishing", "legitimate"]


def test_score_with_one_false_negative(monkeypatch):
    # 兩封都是 phishing，模型漏判一封 → recall = 0.5
    dataset = [
        {"case_id": "a", "body": "釣魚1", "label": "phishing"},
        {"case_id": "b", "body": "釣魚2", "label": "phishing"},
    ]
    _route_by_case(monkeypatch, {"a": "phishing", "b": "legitimate"})
    result = evaluation.score(dataset)
    assert result["recall"] == 0.5
    assert "report" in result and "phishing" in result["report"]


# --- 真實樣本資料可被載入 -------------------------------------------------------
def test_real_labeled_jsonl_loads_and_predicts(monkeypatch):
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "data" / "eval" / "labeled.jsonl"
    dataset = evaluation.load_dataset(path)
    assert len(dataset) > 0
    # 不綁死筆數（資料集會擴充）；只要求 label 皆合法且兩類都存在
    assert {r["label"] for r in dataset} == {"phishing", "legitimate"}

    # mock 出「完美模型」確認資料能跑完評估流程（真實跑分等 GPU）。
    gold = {r["case_id"]: r["label"] for r in dataset}
    monkeypatch.setattr(pipeline.stage1_filter, "run", lambda msg: Stage1Result(label="suspicious", reason="x"))
    monkeypatch.setattr(
        pipeline.stage2_intent,
        "run",
        lambda msg: Stage2Result(
            verdict=gold[msg.case_id], confidence=80, tactics=[], attack_techniques=[], evidence=[], summary="s"
        ),
    )
    monkeypatch.setattr(pipeline.stage3_briefing, "run", lambda s2: Stage3Result(briefing_text="b"))
    result = evaluation.score(dataset)
    assert result["f1"] == 1.0
