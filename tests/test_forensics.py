"""M5：數位鑑識 —— hash 順序、遮蔽、append-only。"""

import hashlib
import json

import pytest

from phishguard import forensics
from phishguard.schema import Message, Stage1Result, Stage2Result, Stage3Result


def _msg(body):
    return Message(case_id="case_fx", sender="victim@example.com", subject="您好", body=body)


def test_sha256_is_of_original_body_AND_log_has_no_original_pii():
    """關鍵：hash 對「原文」算，但存的是「遮蔽版」。

    驗收兩件事同時成立：
      1) 紀錄裡序列化後**找不到**原始 PII（email / 身分證 / 卡號 / 電話）。
      2) 紀錄的 sha256 **等於原文 body 的 sha256**（chain of custody 可驗原件）。
    """
    original_body = (
        "您好 victim@example.com，身分證 A123456789、卡號 1234567812345678、"
        "電話 0912-345-678，請點 http://evil.com/login?id=9999888877776666"
    )
    msg = _msg(original_body)
    s1 = Stage1Result(label="suspicious", reason="可疑連結")

    record = forensics.make_record(msg, s1)
    blob = json.dumps(record, ensure_ascii=False)

    # 1) log 內無原始個人 PII
    for pii in ("victim@example.com", "A123456789", "1234567812345678", "0912-345-678"):
        assert pii not in blob, pii

    # 2) hash 等於「原文」的 hash（不是遮蔽版的 hash）
    expected = hashlib.sha256(original_body.encode("utf-8")).hexdigest()
    assert record["sha256"] == expected

    # 反向確認：遮蔽版的 hash 與存進去的 hash 不同（證明沒有顛倒順序）
    redacted_body = record["message"]["body"]
    assert redacted_body != original_body
    assert hashlib.sha256(redacted_body.encode("utf-8")).hexdigest() != record["sha256"]


def test_attacker_url_survives_in_log():
    """硬規則 5：攻擊者 URL（含長數字）是證據，log 內必須保留。"""
    msg = _msg("請點 http://evil.com/login?id=9999888877776666")
    record = forensics.make_record(msg, Stage1Result(label="suspicious", reason="x"))
    blob = json.dumps(record, ensure_ascii=False)
    assert "http://evil.com/login?id=9999888877776666" in blob


def test_stopped_at_stage1_when_safe():
    record = forensics.make_record(_msg("hi"), Stage1Result(label="safe", reason="ok"))
    assert record["stopped_at"] == "stage1"
    assert "stage2" not in record and "stage3" not in record
    stages = [c["stage"] for c in record["chain_of_custody"]]
    assert stages == ["ingest", "stage1"]


def test_full_chain_of_custody_when_all_stages():
    msg = _msg("hi")
    s1 = Stage1Result(label="suspicious", reason="x")
    s2 = Stage2Result(
        verdict="phishing",
        confidence=90,
        tactics=["緊迫性"],
        attack_techniques=["T1566.002"],
        evidence=["可疑連結 victim@example.com"],
        summary="憑證竊取 victim@example.com",
    )
    s3 = Stage3Result(briefing_text="⚠️ 通知 victim@example.com")
    record = forensics.make_record(msg, s1, s2, s3)

    assert record["stopped_at"] is None
    stages = [c["stage"] for c in record["chain_of_custody"]]
    assert stages == ["ingest", "stage1", "stage2", "stage3"]
    # stage2/stage3 的自由文字也要遮蔽（連 evidence/summary/briefing 裡的 email）
    blob = json.dumps(record, ensure_ascii=False)
    assert "victim@example.com" not in blob
    # 但 ATT&CK ID 不遮蔽
    assert "T1566.002" in record["stage2"]["attack_techniques"]


def test_append_only(monkeypatch, tmp_path):
    monkeypatch.setattr(forensics, "LOG_DIR", tmp_path)
    monkeypatch.setattr(forensics, "AUDIT_PATH", tmp_path / "audit.jsonl")

    r1 = forensics.make_record(_msg("a"), Stage1Result(label="safe", reason="1"))
    r2 = forensics.make_record(_msg("b"), Stage1Result(label="safe", reason="2"))
    forensics.append_audit(r1)
    forensics.append_audit(r2)

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2  # 第二筆未覆寫第一筆
    assert json.loads(lines[0])["stage1"]["reason"] == "1"
    assert json.loads(lines[1])["stage1"]["reason"] == "2"
