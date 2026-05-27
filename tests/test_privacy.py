"""M1 驗收：個人 PII 被遮蔽、攻擊者 URL（IOC）不被遮蔽。"""

from phishguard.privacy import redact


def test_email_is_redacted():
    assert redact("請回信給 victim@example.com 確認") == "請回信給 [EMAIL] 確認"


def test_taiwan_id_is_redacted():
    out = redact("身分證 A123456789 已驗證")
    assert "A123456789" not in out
    assert "[ID]" in out


def test_card_number_is_redacted():
    out = redact("卡號 1234567812345678 請保密")
    assert "1234567812345678" not in out
    assert "[CARD]" in out


def test_phone_is_redacted():
    for phone in ("0912-345-678", "0912345678", "02-12345678"):
        out = redact(f"電話 {phone} 聯絡")
        assert phone not in out, phone
        assert "[PHONE]" in out


def test_attacker_url_is_NOT_redacted():
    """硬規則 5：URL 是證據，連 query 裡的長數字串也必須完整保留。"""
    url = "http://evil-bank.com/verify?id=9876543210987654"
    out = redact(f"請點此 {url} 立即驗證")
    assert url in out  # 整段 URL 原樣
    assert "9876543210987654" in out  # URL 內的 16 位數字未被當成卡號遮掉
    assert "[CARD]" not in out


def test_mixed_pii_and_url():
    """一段同時含個人 PII 與攻擊者 URL 的釣魚文字：PII 全遮、URL 全留。"""
    text = (
        "親愛的 victim@example.com，您的帳戶（身分證 A123456789、"
        "卡號 1234567812345678、電話 0912-345-678）異常，"
        "請至 http://evil-bank.com/login?ref=1234567890123456 重設密碼。"
    )
    out = redact(text)
    # 個人 PII 全部被遮
    for leaked in ("victim@example.com", "A123456789", "1234567812345678", "0912-345-678"):
        assert leaked not in out, leaked
    assert "[EMAIL]" in out and "[ID]" in out and "[CARD]" in out and "[PHONE]" in out
    # 攻擊者 URL（含 16 位 ref 數字）完整保留
    assert "http://evil-bank.com/login?ref=1234567890123456" in out


def test_empty_input_is_safe():
    assert redact("") == ""
    assert redact(None) is None
