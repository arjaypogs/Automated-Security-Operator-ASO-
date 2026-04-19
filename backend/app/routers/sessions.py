"""Session management — one session per assessment (used by MCP server)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models import Finding, Scan
from ..routers.scans import _scan_to_out

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


class SessionCreate(BaseModel):
    target: str
    domain: str = "web"
    depth: str = "standard"
    scope: list[str] = []


class FinishBody(BaseModel):
    summary: str
    recommendations: list[str] = []


@router.post("", status_code=201)
async def create_session(body: SessionCreate, db: AsyncSession = Depends(get_db)):
    """Create a new assessment session (called by MCP server at scan start)."""
    session_id = str(uuid.uuid4())
    scan = Scan(
        id=session_id,
        target=body.target,
        domain=body.domain,
        depth=body.depth,
        scope=json.dumps(body.scope or [body.target]),
        status="running",
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    await db.commit()
    return {
        "session_id": session_id,
        "target": body.target,
        "domain": body.domain,
        "status": "running",
        "message": "Session created. Use session_id in subsequent tool calls.",
    }


@router.get("/{session_id}")
async def get_session(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).where(Scan.id == session_id).options(selectinload(Scan.findings))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Session not found")
    return _scan_to_out(scan)


@router.post("/{session_id}/finish")
async def finish_session(
    session_id: str, body: FinishBody, db: AsyncSession = Depends(get_db)
):
    """Mark session complete and trigger report generation."""
    scan = await db.get(Scan, session_id)
    if not scan:
        raise HTTPException(404, "Session not found")

    scan.status = "completed"
    scan.finished_at = datetime.utcnow()
    scan.summary = body.summary
    if scan.started_at:
        scan.elapsed_seconds = round(
            (scan.finished_at - scan.started_at).total_seconds(), 1
        )

    # Recount findings
    result = await db.execute(
        select(Finding).where(Finding.scan_id == session_id)
    )
    findings = result.scalars().all()
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    scan.finding_counts = json.dumps(counts)

    await db.commit()

    # Trigger report generation
    from ..reports_gen import generate_reports_for_scan
    paths = await generate_reports_for_scan(scan, findings, body.recommendations)

    scan.report_html_path = paths.get("html")
    scan.report_json_path = paths.get("json")
    scan.report_md_path   = paths.get("md")
    scan.report_bb_path   = paths.get("bb")
    await db.commit()

    return {
        "session_id": session_id,
        "status": "completed",
        "finding_counts": counts,
        "reports": paths,
    }
