"""Report download routes."""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{scan_id}/html")
async def download_html(scan_id: str):
    path = _find_report(scan_id, "html")
    return FileResponse(path, media_type="text/html", filename=f"aso_{scan_id}.html")


@router.get("/{scan_id}/json")
async def download_json(scan_id: str):
    path = _find_report(scan_id, "json")
    return FileResponse(path, media_type="application/json", filename=f"aso_{scan_id}.json")


@router.get("/{scan_id}/md")
async def download_md(scan_id: str):
    path = _find_report(scan_id, "md")
    return FileResponse(path, media_type="text/markdown", filename=f"aso_{scan_id}.md")


@router.get("/{scan_id}/bb")
async def download_bugbounty(scan_id: str):
    """Download the bug bounty report pack (HackerOne / Bugcrowd / Intigriti format)."""
    path = _find_report(scan_id, "bb.md")
    return FileResponse(path, media_type="text/markdown", filename=f"bugbounty_{scan_id}.md")


@router.get("/{scan_id}/preview", response_class=HTMLResponse)
async def preview_html(scan_id: str):
    path = _find_report(scan_id, "html")
    return HTMLResponse(content=path.read_text(encoding="utf-8"))


def _find_report(scan_id: str, ext: str) -> Path:
    base = Path("results") / scan_id
    if not base.exists():
        raise HTTPException(404, "Report not found")
    files = sorted(base.glob(f"*.{ext}"))
    if not files:
        raise HTTPException(404, f"No {ext} report for this scan")
    return files[-1]
