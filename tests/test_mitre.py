"""M3：MITRE ATT&CK 對照、驗證與補正。"""

from phishguard import mitre


def test_mapping_table_is_internally_consistent():
    """TACTIC_TO_TECHNIQUE 的每個 technique 都必須是合法 ATTACK_TECHNIQUES ID。"""
    for tid in mitre.TACTIC_TO_TECHNIQUE.values():
        assert tid in mitre.ATTACK_TECHNIQUES, tid


def test_validate_filters_unknown_ids():
    assert mitre.validate_techniques(["T1566.002", "T9999", "garbage", "T1657"]) == [
        "T1566.002",
        "T1657",
    ]


def test_validate_empty():
    assert mitre.validate_techniques([]) == []


def test_enrich_keeps_valid_model_ids_and_dedups():
    out = mitre.enrich_techniques(["T1566.002", "T1566.002"], [])
    assert out == ["T1566.002"]


def test_enrich_drops_invalid_model_ids():
    out = mitre.enrich_techniques(["T9999"], [])
    assert out == []


def test_enrich_augments_from_tactics_substring():
    # 模型沒給 ID，但 tactic 文字含「誘導匯款」→ 補上 T1657。
    out = mitre.enrich_techniques([], ["利用權威誘導匯款至指定帳戶"])
    assert "T1657" in out


def test_enrich_combines_and_dedups_across_sources():
    out = mitre.enrich_techniques(["T1566.002"], ["誘導點擊連結", "誘導匯款"])
    # T1566.002 來自模型 + 「誘導點擊連結」（重複，去重），T1657 來自「誘導匯款」
    assert out == ["T1566.002", "T1657"]


def test_stage3_mitigation_is_user_training():
    # Stage 3 員工警示對應緩解措施：員工教育 = M1017 User Training。
    assert mitre.STAGE3_MITIGATION == "M1017"
    assert mitre.MITIGATIONS["M1017"] == "User Training"
