"""pydantic v2 資料模型：Message / Stage1Result / Stage2Result / Stage3Result。

參考 claude_task_build.md 第 3 節。每個 LLM 回傳的 JSON 都必須用對應 model 驗證，
絕不直接信任或 eval LLM 輸出（CLAUDE.md 慣例）。
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


def _coerce_to_str(item: object) -> str:
    """把單一 evidence/tactic 項目壓平成字串（輸出端韌性，不信任 LLM 形狀）。

    str 原樣保留；dict 取 'value'→'description'→'name'，皆無則 str(整個 dict)；
    其他型別一律 str()。
    """
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for key in ("value", "description", "name"):
            if key in item:
                return str(item[key])
        return str(item)
    return str(item)


def _normalize_str_list(value: object) -> list[str]:
    """把欄位正規化成乾淨的 list[str]，容忍 str / dict / 混雜 / 非 list 輸入。"""
    items = value if isinstance(value, list) else [value]
    return [_coerce_to_str(x) for x in items]


class Channel(str, Enum):
    email = "email"
    line = "line"  # 保留，現階段固定 email（勿擴大範圍）


class Message(BaseModel):
    case_id: str
    channel: Channel = Channel.email
    sender: Optional[str] = None
    subject: Optional[str] = None
    body: str
    urls: list[str] = []
    received_at: Optional[str] = None  # ISO8601


class Stage1Result(BaseModel):
    label: Literal["safe", "suspicious"]
    reason: str
    confidence: Literal["high", "medium", "low"] = "medium"

    # 韌性：本地模型常回大小寫不一或非預期值；mode="before" 正規化，無法辨識則 medium。
    @field_validator("confidence", mode="before")
    @classmethod
    def _normalize_confidence(cls, value: object) -> str:
        s = str(value).strip().lower()
        return s if s in ("high", "medium", "low") else "medium"


class Stage2Result(BaseModel):
    verdict: Literal["phishing", "legitimate"]
    confidence: int = Field(ge=0, le=100)
    tactics: list[str]
    attack_techniques: list[str] = []  # 教授對齊：MITRE ID，如 "T1566.002"
    evidence: list[str]
    summary: str

    # 韌性處理：本地模型常把 tactics/evidence 回成物件陣列（如 {"type","value"}），
    # mode="before" 在驗證前壓平成 list[str]，下游 forensics/STIX 契約不變。
    # 不改成員 B 的 prompt 原意，純粹是輸出端正規化。
    @field_validator("tactics", "evidence", mode="before")
    @classmethod
    def _flatten_str_list(cls, value: object) -> list[str]:
        return _normalize_str_list(value)


class Stage3Result(BaseModel):
    briefing_text: str  # 員工可讀警示（含 emoji 條列）
