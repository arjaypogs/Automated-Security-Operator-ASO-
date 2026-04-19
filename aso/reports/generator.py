"""Report generator — produces HTML, JSON, and Markdown reports from ASO findings."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#2563eb",
    "info":     "#6b7280",
}
_SEVERITY_BG = {
    "critical": "#fef2f2",
    "high":     "#fff7ed",
    "medium":   "#fffbeb",
    "low":      "#eff6ff",
    "info":     "#f9fafb",
}


class ReportGenerator:
    def __init__(self, result: dict, output_dir: str):
        self.result = result
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.meta = result.get("meta", {})
        self.findings = sorted(
            result.get("findings", []),
            key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "info").lower(), 99),
        )
        self.summary = result.get("summary", "")
        self.recommendations = result.get("recommendations", [])
        self._slug = self._make_slug()

    def _make_slug(self) -> str:
        ts = self.meta.get("started_at", datetime.utcnow().isoformat())[:19].replace(":", "").replace("T", "_")
        target = self.meta.get("target", "target").replace("://", "_").replace("/", "_").strip("_")[:30]
        return f"aso_{self.meta.get('domain', 'scan')}_{target}_{ts}"

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def html(self) -> Path:
        out = self.output_dir / f"{self._slug}.html"
        out.write_text(self._render_html(), encoding="utf-8")
        return out

    def json_report(self) -> Path:
        out = self.output_dir / f"{self._slug}.json"
        out.write_text(json.dumps(self.result, indent=2, default=str), encoding="utf-8")
        return out

    def markdown(self) -> Path:
        out = self.output_dir / f"{self._slug}.md"
        out.write_text(self._render_markdown(), encoding="utf-8")
        return out

    # ------------------------------------------------------------------
    # Severity helpers
    # ------------------------------------------------------------------

    def _counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            c[sev] = c.get(sev, 0) + 1
        return c

    # ------------------------------------------------------------------
    # HTML renderer
    # ------------------------------------------------------------------

    def _render_html(self) -> str:
        counts = self._counts()
        findings_html = "\n".join(self._finding_card(i, f) for i, f in enumerate(self.findings))
        recs_html = "".join(f"<li>{r}</li>" for r in self.recommendations)
        stat_cards = "".join(
            f'<div class="stat-card" style="border-left:4px solid {_SEVERITY_COLORS.get(s, "#6b7280")}">'
            f'<span class="stat-num">{counts.get(s, 0)}</span>'
            f'<span class="stat-label">{s.upper()}</span></div>'
            for s in ["critical", "high", "medium", "low", "info"]
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ASO Security Report — {self.meta.get('target', '')}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
             border-bottom: 2px solid #dc2626; padding: 2rem; }}
  .header h1 {{ font-size: 2rem; color: #f8fafc; }}
  .header .subtitle {{ color: #94a3b8; margin-top: 0.25rem; }}
  .header .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 1rem; margin-top: 1.5rem; }}
  .meta-item {{ background: #1e293b; padding: 0.75rem 1rem; border-radius: 8px; }}
  .meta-item label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
  .meta-item span {{ display: block; font-weight: 600; color: #f1f5f9; margin-top: 0.25rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 2rem 0; }}
  .stat-card {{ flex: 1; min-width: 120px; background: #1e293b; padding: 1rem;
                border-radius: 8px; text-align: center; }}
  .stat-num {{ display: block; font-size: 2rem; font-weight: 700; color: #f1f5f9; }}
  .stat-label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; }}
  .section-title {{ font-size: 1.25rem; font-weight: 700; color: #f1f5f9; margin: 2rem 0 1rem;
                    padding-bottom: 0.5rem; border-bottom: 1px solid #334155; }}
  .summary-box {{ background: #1e293b; padding: 1.5rem; border-radius: 8px;
                  border-left: 4px solid #3b82f6; color: #cbd5e1; white-space: pre-wrap; }}
  .finding {{ background: #1e293b; border-radius: 8px; margin-bottom: 1rem;
              border: 1px solid #334155; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 1rem; padding: 1rem 1.5rem;
                     cursor: pointer; }}
  .finding-header:hover {{ background: #263247; }}
  .severity-badge {{ padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem;
                     font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; }}
  .finding-title {{ font-weight: 600; color: #f1f5f9; flex: 1; }}
  .finding-meta {{ font-size: 0.8rem; color: #64748b; }}
  .finding-body {{ padding: 1.5rem; border-top: 1px solid #334155; display: none; }}
  .finding-body.open {{ display: block; }}
  .field-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;
                  color: #64748b; margin-bottom: 0.25rem; margin-top: 1rem; }}
  .field-label:first-child {{ margin-top: 0; }}
  .field-value {{ color: #cbd5e1; background: #0f172a; padding: 0.75rem; border-radius: 4px;
                  white-space: pre-wrap; font-size: 0.9rem; }}
  .code-block {{ font-family: 'Courier New', monospace; background: #0f172a; color: #86efac;
                 padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem;
                 white-space: pre-wrap; }}
  .refs {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }}
  .ref-link {{ background: #1e3a5f; color: #93c5fd; padding: 0.2rem 0.6rem; border-radius: 4px;
               font-size: 0.8rem; text-decoration: none; }}
  .recs {{ background: #1e293b; padding: 1.5rem; border-radius: 8px; }}
  .recs li {{ margin-bottom: 0.5rem; color: #cbd5e1; padding-left: 0.5rem; }}
  .footer {{ text-align: center; color: #475569; padding: 2rem; font-size: 0.85rem;
             border-top: 1px solid #1e293b; margin-top: 3rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>&#x1F6E1; ASO Security Report</h1>
  <p class="subtitle">Automated Security Operator — AI Pentest Agent</p>
  <div class="meta-grid">
    <div class="meta-item"><label>Target</label><span>{self.meta.get('target','')}</span></div>
    <div class="meta-item"><label>Domain</label><span>{self.meta.get('domain_label','')}</span></div>
    <div class="meta-item"><label>Depth</label><span>{self.meta.get('depth','')}</span></div>
    <div class="meta-item"><label>Started</label><span>{self.meta.get('started_at','')[:19].replace('T',' ')}</span></div>
    <div class="meta-item"><label>Duration</label><span>{self.meta.get('elapsed_seconds',0)}s</span></div>
    <div class="meta-item"><label>Findings</label><span>{len(self.findings)}</span></div>
  </div>
</div>

<div class="container">
  <div class="stats">{stat_cards}</div>

  <div class="section-title">Executive Summary</div>
  <div class="summary-box">{self.summary or 'No summary provided.'}</div>

  <div class="section-title">Findings ({len(self.findings)})</div>
  {findings_html or '<p style="color:#64748b">No findings recorded.</p>'}

  <div class="section-title">Recommendations</div>
  <div class="recs"><ul>{recs_html or '<li>No recommendations provided.</li>'}</ul></div>
</div>

<div class="footer">
  Generated by ASO v{self.meta.get('aso_version','1.0.0')} &bull; {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
</div>

<script>
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => {{
    const body = h.nextElementSibling;
    body && body.classList.toggle('open');
  }});
}});
</script>
</body>
</html>"""

    def _finding_card(self, idx: int, f: dict) -> str:
        sev = f.get("severity", "info").lower()
        color = _SEVERITY_COLORS.get(sev, "#6b7280")
        bg = _SEVERITY_BG.get(sev, "#f9fafb")
        refs = f.get("references", [])
        refs_html = "".join(f'<a class="ref-link" href="{r}" target="_blank">{r[:60]}</a>' for r in refs)
        cvss = f.get("cvss_score")
        cvss_str = f"CVSS {cvss}" if cvss else ""
        cwe = f.get("cwe", "")
        meta_parts = [x for x in [cwe, cvss_str] if x]
        meta_str = " &bull; ".join(meta_parts)

        return f"""<div class="finding">
  <div class="finding-header">
    <span class="severity-badge" style="background:{color};color:#fff">{sev.upper()}</span>
    <span class="finding-title">{f.get('title','Untitled')}</span>
    <span class="finding-meta">{meta_str}</span>
  </div>
  <div class="finding-body">
    <div class="field-label">Description</div>
    <div class="field-value">{f.get('description','')}</div>
    <div class="field-label">Evidence / Reproduction</div>
    <div class="code-block">{f.get('evidence','')}</div>
    <div class="field-label">Remediation</div>
    <div class="field-value">{f.get('remediation','')}</div>
    {('<div class="field-label">References</div><div class="refs">' + refs_html + '</div>') if refs else ''}
  </div>
</div>"""

    # ------------------------------------------------------------------
    # Markdown renderer
    # ------------------------------------------------------------------

    def _render_markdown(self) -> str:
        counts = self._counts()
        lines = [
            f"# ASO Security Report",
            f"",
            f"**Target:** {self.meta.get('target','')}  ",
            f"**Domain:** {self.meta.get('domain_label','')}  ",
            f"**Depth:** {self.meta.get('depth','')}  ",
            f"**Date:** {self.meta.get('started_at','')[:10]}  ",
            f"**Duration:** {self.meta.get('elapsed_seconds',0)}s  ",
            f"",
            f"## Summary",
            f"",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            n = counts.get(sev, 0)
            if n:
                lines.append(f"- **{sev.upper()}**: {n}")
        lines += ["", self.summary or "_No summary provided._", ""]

        lines += ["## Findings", ""]
        if not self.findings:
            lines.append("_No findings recorded._")
        for f in self.findings:
            sev = f.get("severity", "info").upper()
            lines += [
                f"### [{sev}] {f.get('title','Untitled')}",
                f"",
                f"**Severity:** {sev}  ",
            ]
            if f.get("cwe"):
                lines.append(f"**CWE:** {f['cwe']}  ")
            if f.get("cvss_score"):
                lines.append(f"**CVSS:** {f['cvss_score']}  ")
            lines += [
                "",
                f"**Description:**  ",
                f"{f.get('description','')}",
                "",
                f"**Evidence:**",
                f"```",
                f"{f.get('evidence','')}",
                f"```",
                "",
                f"**Remediation:**  ",
                f"{f.get('remediation','')}",
                "",
            ]
            if f.get("references"):
                lines += ["**References:**"]
                for r in f["references"]:
                    lines.append(f"- {r}")
                lines.append("")

        lines += ["## Recommendations", ""]
        if not self.recommendations:
            lines.append("_No recommendations provided._")
        for r in self.recommendations:
            lines.append(f"- {r}")

        lines += [
            "",
            "---",
            f"_Report generated by ASO v{self.meta.get('aso_version','1.0.0')}_",
        ]
        return "\n".join(lines)
