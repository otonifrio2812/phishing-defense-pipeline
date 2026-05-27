"""資料交換標準：STIX 2.1 IOC 匯出（硬規則 2）。

把攻擊者的可疑 URL / 網域 / 寄件者包成 STIX 2.1 Indicator bundle，讓 IOC 可被交換 / 比對。
這些是**攻擊者 IOC、是證據，不遮蔽**（硬規則 5）—— 與 forensics 對受害者 PII 的遮蔽相反。
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import stix2

from .schema import Message, Stage2Result

REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports"


def _escape(value: str) -> str:
    """避免單引號破壞 STIX pattern 字串。"""
    return value.replace("'", "%27")


def _domain_of(url: str) -> Optional[str]:
    host = urlparse(url).hostname
    return host or None


def to_stix_bundle(msg: Message, s2: Stage2Result) -> Optional[stix2.Bundle]:
    """把 msg 的 URL / 網域 / 寄件者包成 STIX Indicator bundle。

    無任何可匯出的 IOC 時回傳 None（呼叫端據此決定是否寫檔）。
    """
    indicators: list[stix2.Indicator] = []
    seen_domains: set[str] = set()

    for url in msg.urls:
        indicators.append(
            stix2.Indicator(
                name="Phishing URL",
                pattern=f"[url:value = '{_escape(url)}']",
                pattern_type="stix",
            )
        )
        dom = _domain_of(url)
        if dom and dom not in seen_domains:
            seen_domains.add(dom)
            indicators.append(
                stix2.Indicator(
                    name="Phishing domain",
                    pattern=f"[domain-name:value = '{_escape(dom)}']",
                    pattern_type="stix",
                )
            )

    if msg.sender:
        indicators.append(
            stix2.Indicator(
                name="Phishing sender",
                pattern=f"[email-addr:value = '{_escape(msg.sender)}']",
                pattern_type="stix",
            )
        )

    if not indicators:
        return None
    return stix2.Bundle(*indicators)


def write_bundle(msg: Message, s2: Stage2Result) -> Optional[Path]:
    """產生並寫出 reports/<case_id>.stix.json。無 IOC 時不寫檔、回傳 None。"""
    bundle = to_stix_bundle(msg, s2)
    if bundle is None:
        return None
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"{msg.case_id}.stix.json"
    path.write_text(bundle.serialize(pretty=True), encoding="utf-8")
    return path
