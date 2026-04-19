"""Scan CRUD routes + WebSocket streaming."""

from __future__ import annotations

import json
import uuid
from typing import AsyncGenerator

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models import Finding, Scan
from ..runner import manager, run_scan
from ..schemas import FindingOut, ScanCreate, ScanOut

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _scan_to_out(scan: Scan) -> ScanOut:
    findings_out = [
        FindingOut(
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
        for f in scan.findings
    ]
    return ScanOut(
        id=scan.id,
        target=scan.target,
        domain=scan.domain,
        depth=scan.depth,
        status=scan.status,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        elapsed_seconds=scan.elapsed_seconds,
        finding_counts=json.loads(scan.finding_counts or "{}"),
        summary=scan.summary,
        report_html_path=scan.report_html_path,
        report_json_path=scan.report_json_path,
        report_md_path=scan.report_md_path,
        findings=findings_out,
    )


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    scan_id = str(uuid.uuid4())
    scope = body.scope or [body.target]
    scan = Scan(
        id=scan_id,
        target=body.target,
        domain=body.domain,
        depth=body.depth,
        scope=json.dumps(scope),
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(
        run_scan,
        scan_id=scan_id,
        target=body.target,
        domain=body.domain,
        depth=body.depth,
        scope=scope,
        report_format=body.report_format,
    )
    return _scan_to_out(scan)


@router.get("", response_model=list[ScanOut])
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).options(selectinload(Scan.findings)).order_by(Scan.started_at.desc().nullslast())
    )
    return [_scan_to_out(s) for s in result.scalars().all()]


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _scan_to_out(scan)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    await db.delete(scan)
    await db.commit()


@router.websocket("/{scan_id}/ws")
async def scan_ws(scan_id: str, ws: WebSocket, db: AsyncSession = Depends(get_db)):
    """Stream real-time scan output to the browser."""
    await manager.connect(scan_id, ws)
    try:
        # Send current status immediately so the client can catch up
        scan = await db.get(Scan, scan_id)
        if scan:
            await ws.send_text(json.dumps({"type": "status", "status": scan.status}))
        while True:
            # Keep alive — client can send pings
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(scan_id, ws)
