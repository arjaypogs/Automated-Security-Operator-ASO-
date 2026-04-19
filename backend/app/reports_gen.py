"""Report generation helper called from session finisher."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .models import Finding, Scan


async def generate_reports_for_scan(
    scan: Scan,
    findings: list[Finding],
    recommendations: list[str],
) -> dict[str, str]:
    """Build JSON result dict and invoke ReportGenerator."""
    import sys

    sys.path.insert(0, "/app")
    from aso.reports.generator import ReportGenerator

    output_dir = Path("results") / scan.id
    output_dir.mkdir(parents=True, exist_ok=True)

    findings_data = [
        {
            "title":       f.title,
            "severity":    f.severity,
            "cwe":         f.cwe,
            "cvss_score":  f.cvss_score,
            "description": f.description,
            "evidence":    f.evidence,
            "remediation": f.remediation,
            "references":  f.references_list,
        }
        for f in findings
    ]

    result = {
        "meta": {
            "target":         scan.target,
            "domain":         scan.domain,
            "domain_label":   scan.domain.upper(),
            "scope":          json.loads(scan.scope or "[]"),
            "depth":          scan.depth,
            "started_at":     scan.started_at.isoformat() + "Z" if scan.started_at else "",
            "finished_at":    scan.finished_at.isoformat() + "Z" if scan.finished_at else "",
            "elapsed_seconds": scan.elapsed_seconds or 0,
            "aso_version":    "1.0.0",
        },
        "findings":        findings_data,
        "summary":         scan.summary or "",
        "recommendations": recommendations,
    }

    gen = ReportGenerator(result, str(output_dir))
    paths: dict[str, str] = {}
    paths["html"] = str(gen.html())
    paths["json"] = str(gen.json_report())
    paths["md"]   = str(gen.markdown())
    return paths
