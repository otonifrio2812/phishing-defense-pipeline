"""pydantic v2 資料模型：Message / Stage1Result / Stage2Result / Stage3Result。

參考 claude_task_build.md 第 3 節。每個 LLM 回傳的 JSON 都必須用對應 model 驗證，
絕不直接信任或 eval LLM 輸出（CLAUDE.md 慣例）。
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


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


class Stage2Result(BaseModel):
    verdict: Literal["phishing", "legitimate"]
    confidence: int = Field(ge=0, le=100)
    tactics: list[str]
    attack_techniques: list[str] = []  # 教授對齊：MITRE ID，如 "T1566.002"
    evidence: list[str]
    summary: str


class Stage3Result(BaseModel):
    briefing_text: str  # 員工可讀警示（含 emoji 條列）
