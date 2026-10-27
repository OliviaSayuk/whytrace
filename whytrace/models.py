from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class SourceSpec(BaseModel):
    id: str
    kind: str
    path: str


class CaseMeta(BaseModel):
    id: str
    title: str
    org: str
    opened_at: str
    question: str
    sources: list[SourceSpec]


class Event(BaseModel):
    id: str
    ts: str
    source: str
    action: str
    result: str | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    bytes_out: int | None = None
    process: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    object: str | None = None
    pid: int | None = None
    ppid: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Detection(BaseModel):
    id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    mitre: list[str]
    why_rule: str
    event_ids: list[str]
    entities: dict[str, list[str]] = Field(default_factory=dict)
    score: float


class Chain(BaseModel):
    id: str
    title: str
    user: str | None
    hosts: list[str]
    start_ts: str
    end_ts: str
    detection_ids: list[str]
    event_ids: list[str]
    score: float


class Evidence(BaseModel):
    event_id: str
    note: str


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    hypothesis: str
    why: str
    mitre: list[str]
    evidence: list[Evidence]
    next_steps: list[str]
    chain_id: str | None = None


class Report(BaseModel):
    case_id: str
    question: str
    verdict: str
    confidence: Literal["low", "medium", "high"]
    executive_summary: str
    findings: list[Finding]
    narrative: list[str]
    unanswered: list[str]
    model: str
    source_counts: dict[str, int]
