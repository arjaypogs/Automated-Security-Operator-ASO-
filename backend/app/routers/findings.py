"""Standalone findings CRUD — used by MCP server to save/retrieve findings."""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Finding
from ..schemas import FindingOut

router = APIRouter(prefix="/api/findings", tags=["findings"])


class FindingCreate(BaseModel):
    title: str
    severity: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: str | None = None
    cvss_score: float | None = None
    references: list[str] = []
    session_id: str | None = None   # maps to scan_id in DB


@router.post("", response_model=FindingOut, status_code=201)
async def create_finding(body: FindingCreate, db: AsyncSession = Depends(get_db)):
    if not body.session_id:
        raise HTTPException(400, "session_id is required")
    finding = Finding(
        scan_id=body.session_id,
        title=body.title,
        severity=body.severity.lower(),
        cwe=body.cwe,
        cvss_score=body.cvss_score,
        description=body.description,
        evidence=body.evidence,
        remediation=body.remediation,
        references=json.dumps(body.references),
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)
    return _to_out(finding)


@router.get("", response_model=list[FindingOut])
async def list_findings(
    session_id: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Finding)
    if session_id:
        q = q.where(Finding.scan_id == session_id)
    result = await db.execute(q.order_by(Finding.id.desc()))
    return [_to_out(f) for f in result.scalars().all()]


def _to_out(f: Finding) -> FindingOut:
    return FindingOut(
        id=f.id,
        scan_id=f.scan_id,
        title=f.title,
        severity=f.severity,
        cwe=f.cwe,
        cvss_score=f.cvss_score,
        description=f.description,
        evidence=f.evidence,
        remediation=f.remediation,
        references=f.references_list,
    )
