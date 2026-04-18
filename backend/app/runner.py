"""Scan runner — executes ASO agent as subprocess and streams output via WebSocket."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import WebSocket

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# ANSI escape code stripper
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m|\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class ConnectionManager:
    """Manages WebSocket connections per scan_id."""

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, scan_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: str, ws: WebSocket) -> None:
        conns = self._connections.get(scan_id, [])
        if ws in conns:
            conns.remove(ws)

    async def send(self, scan_id: str, msg: dict) -> None:
        text = json.dumps(msg)
        dead = []
        for ws in self._connections.get(scan_id, []):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)

    async def broadcast_output(self, scan_id: str, text: str) -> None:
        await self.send(scan_id, {"type": "output", "text": text})

    async def broadcast_status(self, scan_id: str, status: str) -> None:
        await self.send(scan_id, {"type": "status", "status": status})

    async def broadcast_finding(self, scan_id: str, finding: dict) -> None:
        await self.send(scan_id, {"type": "finding", "data": finding})


manager = ConnectionManager()


async def run_scan(scan_id: str, target: str, domain: str, depth: str,
                   scope: list[str], report_format: str) -> None:
    """
    Run the ASO agent as a subprocess and stream output to connected WebSocket clients.
    Updates the scan record in the database when done.
    """
    from .database import AsyncSessionLocal
    from .models import Scan, Finding

    output_dir = Path("results") / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    await manager.broadcast_status(scan_id, "running")
    await manager.broadcast_output(scan_id, f"[ASO] Starting scan: {target} ({domain}, {depth})\n")

    # Build CLI command (main.py is at project root /app)
    cmd = [
        sys.executable, "/app/main.py", "scan",
        "--target", target,
        "--domain", domain,
        "--depth", depth,
        "--output", str(output_dir),
        "--format", "json",
        "--no-banner",
    ]
    for s in scope:
        cmd.extend(["--scope", s])

    env = {**os.environ, "NO_COLOR": "1", "FORCE_COLOR": "0"}
    tester_url = os.getenv("TOOL_RUNNER_URL", "")
    if tester_url:
        env["TOOL_RUNNER_URL"] = tester_url

    started = datetime.utcnow()

    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan:
            scan.status = "running"
            scan.started_at = started
            await db.commit()

    result_json: dict = {}
    error_msg: str | None = None

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )

        # Stream stdout line by line
        assert proc.stdout
        async for raw_line in proc.stdout:
            line = strip_ansi(raw_line.decode("utf-8", errors="replace"))
            await manager.broadcast_output(scan_id, line)

        await proc.wait()

        # Find the JSON result file written by ASO
        json_files = sorted(output_dir.glob("*.json"))
        if json_files:
            with open(json_files[-1]) as f:
                result_json = json.load(f)
            await manager.broadcast_output(scan_id, "\n[ASO] Scan complete. Saving results...\n")

            # Broadcast individual findings
            for finding in result_json.get("findings", []):
                await manager.broadcast_finding(scan_id, finding)

        if proc.returncode != 0 and not json_files:
            error_msg = f"Process exited with code {proc.returncode}"

    except asyncio.CancelledError:
        error_msg = "Scan was cancelled"
    except Exception as exc:
        error_msg = str(exc)
        await manager.broadcast_output(scan_id, f"\n[ERROR] {exc}\n")

    finished = datetime.utcnow()
    elapsed = (finished - started).total_seconds()

    # Persist results to database
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            return

        if error_msg and not result_json:
            scan.status = "failed"
            scan.error_message = error_msg
        else:
            scan.status = "completed"
            scan.finished_at = finished
            scan.elapsed_seconds = round(elapsed, 1)
            scan.summary = result_json.get("summary", "")

            meta = result_json.get("meta", {})
            findings_list = result_json.get("findings", [])
            counts: dict[str, int] = {}

            for f_data in findings_list:
                sev = f_data.get("severity", "info").lower()
                counts[sev] = counts.get(sev, 0) + 1
                finding = Finding(
                    scan_id=scan_id,
                    title=f_data.get("title", "Untitled"),
                    severity=sev,
                    cwe=f_data.get("cwe"),
                    cvss_score=f_data.get("cvss_score"),
                    description=f_data.get("description", ""),
                    evidence=f_data.get("evidence", ""),
                    remediation=f_data.get("remediation", ""),
                    references=json.dumps(f_data.get("references", [])),
                )
                db.add(finding)

            scan.finding_counts = json.dumps(counts)

            # Link report files
            html_files = sorted(output_dir.glob("*.html"))
            json_files2 = sorted(output_dir.glob("*.json"))
            md_files = sorted(output_dir.glob("*.md"))
            if html_files:
                scan.report_html_path = str(html_files[-1])
            if json_files2:
                scan.report_json_path = str(json_files2[-1])
            if md_files:
                scan.report_md_path = str(md_files[-1])

        await db.commit()

    status = scan.status if scan else ("failed" if error_msg else "completed")
    await manager.broadcast_status(scan_id, status)
    await manager.broadcast_output(scan_id, f"[ASO] Status: {status}\n")
