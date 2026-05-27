"""M5：整合測試 —— mock 掉三個 stage 回傳，驗證 pipeline 串接、鑑識落地、IOC 匯出。

全程不打真實 LLM、不需 .env：monkeypatch stage1/2/3 的 run()，並把 logs/ reports/
重導到 tmp_path。
"""

import hashlib
import json

import pytest

from phishguard import forensics, ioc, pipeline
from phishguard.schema import Message, Stage1Result, Stage2Result, Stage3Result


@pytest.fixture(autouse=True)
def _redirect_outputs(monkeypatch, tmp_path):
    """把鑑識日誌與 STIX 報告導到暫存目錄，避免污染專案 logs/ reports/。"""
    monkeypatch.setattr(forensics, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(forensics, "AUDIT_PATH", tmp_path / "logs" / "audit.jsonl")
    monkeypatch.setattr(ioc, "REPORTS_DIR", tmp_path / "reports")
    return tmp_path


def _stub_stages(monkeypatch, s1, s2=None, s3=None):
    monkeypatch.setattr(pipeline.stage1_filter, "run", lambda msg: s1)
    if s2 is not None:
        monkeypatch.setattr(pipeline.stage2_intent, "run", lambda msg: s2)
    if s3 is not None:
        monkeypatch.setattr(pipeline.stage3_briefing, "run", lambda s2_in: s3)


def _phishing_msg():
    return Message(
        case_id="case_ph",
        sender="attacker@evil.com",
        subject="您的帳戶異常",
        body="您好 victim@example.com，請點 http://evil.com/login?id=9999888877776666 重設密碼",
        urls=["http://evil.com/login?id=9999888877776666"],
    )


def _audit_lines(tmp_path):
    p = tmp_path / "logs" / "audit.jsonl"
    if not p.exists():
        return []
    return p.read_text(encoding="utf-8").splitlines()


# --- safe：停在 Stage 1 ---------------------------------------------------------
def test_safe_stops_at_stage1_no_stix(monkeypatch, _redirect_outputs):
    tmp_path = _redirect_outputs
    _stub_stages(monkeypatch, Stage1Result(label="safe", reason="內部例行通知"))

    result = pipeline.process(
        Message(case_id="case_safe", body="下週一開會通知，請確認出席")
    )

    assert result["stopped_at"] == "stage1"
    assert result["stix_path"] is None
    assert "stage2" not in result
    lines = _audit_lines(tmp_path)
    assert len(lines) == 1
    assert not (tmp_path / "reports").exists()  # safe 不匯出 IOC


# --- phishing：跑完三階段 + 鑑識 + STIX ----------------------------------------
def test_phishing_full_flow(monkeypatch, _redirect_outputs):
    tmp_path = _redirect_outputs
    msg = _phishing_msg()
    s2 = Stage2Result(
        verdict="phishing",
        confidence=93,
        tactics=["緊迫性", "誘導點擊連結"],
        attack_techniques=["T1566.002"],
        evidence=["可疑連結", "仿冒登入頁 victim@example.com"],
        summary="憑證竊取釣魚，受害者 victim@example.com",
    )
    s3 = Stage3Result(briefing_text="⚠️ 警示 victim@example.com 請勿點擊")
    _stub_stages(monkeypatch, Stage1Result(label="suspicious", reason="可疑連結"), s2, s3)

    result = pipeline.process(msg)

    # 1) audit.jsonl 多一筆，且 sha256 == 原文 body 的 hash
    lines = _audit_lines(tmp_path)
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["sha256"] == hashlib.sha256(msg.body.encode("utf-8")).hexdigest()

    # 2) log 內無未遮蔽個資（連 stage2/stage3 文字裡的 email 也要遮）
    assert "victim@example.com" not in lines[0]
    # 3) 但攻擊者 URL（IOC）保留
    assert "http://evil.com/login?id=9999888877776666" in lines[0]

    # 4) reports/<case_id>.stix.json 產出，且是合法 STIX bundle
    stix_file = tmp_path / "reports" / "case_ph.stix.json"
    assert stix_file.exists()
    assert result["stix_path"] == str(stix_file)
    bundle = json.loads(stix_file.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert any("evil.com" in p for p in patterns)

    # 5) process() 回傳的也是遮蔽版（對外輸出不洩漏 PII）
    assert "victim@example.com" not in json.dumps(result, ensure_ascii=False)


# --- suspicious 但 Stage 2 判 legitimate：寫鑑識、但不匯出 STIX -----------------
def test_suspicious_then_legitimate_no_stix(monkeypatch, _redirect_outputs):
    tmp_path = _redirect_outputs
    msg = _phishing_msg()
    s2 = Stage2Result(
        verdict="legitimate",
        confidence=20,
        tactics=[],
        attack_techniques=[],
        evidence=[],
        summary="實為正常通知",
    )
    s3 = Stage3Result(briefing_text="（僅供參考）")
    _stub_stages(monkeypatch, Stage1Result(label="suspicious", reason="保守標記"), s2, s3)

    result = pipeline.process(msg)

    assert len(_audit_lines(tmp_path)) == 1  # 仍寫鑑識紀錄
    assert result["stix_path"] is None
    assert not (tmp_path / "reports").exists()  # 非 phishing 不匯出 IOC


# --- append-only：連跑兩封 ------------------------------------------------------
def test_audit_is_append_only_across_runs(monkeypatch, _redirect_outputs):
    tmp_path = _redirect_outputs
    _stub_stages(monkeypatch, Stage1Result(label="safe", reason="ok"))

    pipeline.process(Message(case_id="c1", body="開會通知"))
    pipeline.process(Message(case_id="c2", body="薪資單通知"))

    lines = _audit_lines(tmp_path)
    assert len(lines) == 2
    assert json.loads(lines[0])["case_id"] == "c1"
    assert json.loads(lines[1])["case_id"] == "c2"
