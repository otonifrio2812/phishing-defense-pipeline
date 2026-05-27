"""M5：STIX 2.1 IOC 匯出。"""

import json

from phishguard import ioc
from phishguard.schema import Message, Stage2Result


def _s2():
    return Stage2Result(
        verdict="phishing",
        confidence=90,
        tactics=["誘導點擊連結"],
        attack_techniques=["T1566.002"],
        evidence=["可疑連結"],
        summary="釣魚",
    )


def _msg(**kw):
    return Message(case_id="case_ioc", body="點此", **kw)


def test_bundle_contains_url_domain_sender_indicators():
    msg = _msg(sender="attacker@evil.com", urls=["http://evil.com/login"])
    bundle = ioc.to_stix_bundle(msg, _s2())
    data = json.loads(bundle.serialize())
    patterns = [o["pattern"] for o in data["objects"] if o["type"] == "indicator"]

    assert any("url:value = 'http://evil.com/login'" in p for p in patterns)
    assert any("domain-name:value = 'evil.com'" in p for p in patterns)
    # 硬規則 5：攻擊者寄件者是 IOC，原樣保留、不遮蔽
    assert any("email-addr:value = 'attacker@evil.com'" in p for p in patterns)


def test_all_objects_are_spec_version_21():
    msg = _msg(urls=["http://evil.com/a"])
    data = json.loads(ioc.to_stix_bundle(msg, _s2()).serialize())
    for obj in data["objects"]:
        assert obj["spec_version"] == "2.1"


def test_no_iocs_returns_none():
    # 沒有 urls、沒有 sender → 無可匯出 IOC
    assert ioc.to_stix_bundle(_msg(), _s2()) is None


def test_write_bundle_creates_file(monkeypatch, tmp_path):
    monkeypatch.setattr(ioc, "REPORTS_DIR", tmp_path)
    msg = _msg(urls=["http://evil.com/login"])
    path = ioc.write_bundle(msg, _s2())
    assert path == tmp_path / "case_ioc.stix.json"
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8"))["type"] == "bundle"


def test_write_bundle_none_when_no_iocs(monkeypatch, tmp_path):
    monkeypatch.setattr(ioc, "REPORTS_DIR", tmp_path)
    assert ioc.write_bundle(_msg(), _s2()) is None
    assert list(tmp_path.iterdir()) == []  # 沒寫任何檔
