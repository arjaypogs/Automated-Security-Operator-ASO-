"""Pydantic v2 schemas for request/response validation."""

from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel


class ScanCreate(BaseModel):
    target: str
    domain: str = "auto"
    depth: str = "standard"
    scope: list[str] = []
    report_format: str = "html"


class FindingOut(BaseModel):
    id: int
    scan_id: str
    title: str
    severity: str
    cwe: str | None
    cvss_score: float | None
    description: str
    steps_to_reproduce: list[str] = []
    evidence: str
    impact: str = ""
    remediation: str
    references: list[str]

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: str
    target: str
    domain: str
    depth: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    elapsed_seconds: float | None
    finding_counts: dict[str, int]
    summary: str | None
    report_html_path: str | None
    report_json_path: str | None
    report_md_path: str | None
    report_bb_path: str | None
    findings: list[FindingOut] = []

    model_config = {"from_attributes": True}


class WsMessage(BaseModel):
    type: str           # output | finding | status | error
    text: str | None = None
    data: Any = None
    status: str | None = None
