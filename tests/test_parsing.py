"""M3：共用解析工具 parsing.py。"""

import pytest

from phishguard.parsing import extract_json, parse_with_retry, render_message
from phishguard.schema import Message, Stage1Result


def test_render_includes_present_fields_only():
    out = render_message(Message(case_id="t", body="hi"))
    assert "內文：hi" in out
    assert "寄件者" not in out and "主旨" not in out and "連結" not in out

    out2 = render_message(
        Message(case_id="t", body="hi", sender="a@b.com", subject="s", urls=["http://x"])
    )
    assert "寄件者：a@b.com" in out2 and "主旨：s" in out2 and "連結：http://x" in out2


def test_extract_json_plain():
    assert extract_json('{"a": 1}') == '{"a": 1}'


def test_extract_json_strips_fence():
    assert extract_json('```json\n{"a": 1}\n```') == '{"a": 1}'


def test_extract_json_ignores_surrounding_prose():
    assert extract_json('結果如下：{"a": 1} 以上') == '{"a": 1}'


def test_extract_json_raises_when_no_object():
    with pytest.raises(ValueError, match="找不到 JSON"):
        extract_json("完全沒有大括號")


def test_parse_with_retry_succeeds_first_try():
    r = parse_with_retry(lambda: '{"label": "safe", "reason": "ok"}', Stage1Result)
    assert r.label == "safe"


def test_parse_with_retry_retries_once():
    seq = iter(["壞的", '{"label": "safe", "reason": "ok"}'])
    r = parse_with_retry(lambda: next(seq), Stage1Result)
    assert r.label == "safe"


def test_parse_with_retry_raises_after_attempts():
    with pytest.raises(ValueError, match="共嘗試 2 次"):
        parse_with_retry(lambda: "永遠壞的", Stage1Result)
