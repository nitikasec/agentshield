"""Render an AgentShield Report as plain text (terminal) or a self-contained HTML file."""
from __future__ import annotations

import datetime
import html

from .analyzer import Report

_SEV_COLOR = {"CRITICAL": "#b31412", "HIGH": "#d93025", "MEDIUM": "#e37400",
              "LOW": "#1a73e8", "INFO": "#5f6368"}
_RATING_COLOR = {"CRITICAL": "#b31412", "HIGH": "#d93025", "MEDIUM": "#e37400",
                 "LOW": "#1a73e8", "CLEAN": "#188038"}


def to_text(report: Report, target: str = "") -> str:
    lines = [
        "AgentShield — MCP Config Security Report",
        f"Target: {target}" if target else "",
        f"Risk score: {report.risk_score}/100  ({report.rating})",
        f"Servers analyzed: {report.servers_analyzed} | "
        f"Confirmed: {len(report.confirmed)} | Indicators (need review): {len(report.indicators)}",
        "-" * 64,
    ]
    if not report.findings:
        lines.append("No issues found by the static checks.")
    for f in report.findings:
        lines.append(f"[{f.severity}/{f.confidence}] {f.title}")
        lines.append(f"    where: {f.where}")
        lines.append(f"    evidence: {f.evidence}")
        lines.append(f"    fix: {f.recommendation}")
        lines.append("")
    lines.append("Note: 'indicator' findings are heuristic and require manual confirmation.")
    return "\n".join(l for l in lines if l is not None)


def to_html(report: Report, target: str = "") -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    rc = _RATING_COLOR.get(report.rating, "#5f6368")
    rows = []
    for f in report.findings:
        sc = _SEV_COLOR.get(f.severity, "#5f6368")
        badge = ("✔ confirmed" if f.confidence == "confirmed" else "? indicator")
        bcol = "#188038" if f.confidence == "confirmed" else "#e37400"
        rows.append(f"""
        <div class="finding">
          <div class="fhead">
            <span class="sev" style="background:{sc}">{html.escape(f.severity)}</span>
            <span class="conf" style="color:{bcol}">{badge}</span>
            <span class="cat">{html.escape(f.category)}</span>
            <b>{html.escape(f.title)}</b>
          </div>
          <div class="meta"><code>{html.escape(f.where)}</code></div>
          <div class="ev">evidence: {html.escape(f.evidence)}</div>
          <div class="fix">fix: {html.escape(f.recommendation)}</div>
        </div>""")
    body = "\n".join(rows) or "<p>No issues found by the static checks.</p>"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AgentShield Report</title><style>
*{{font-family:-apple-system,Arial,sans-serif;box-sizing:border-box}}
body{{margin:0;background:#f6f8fa;color:#1a1a1a}}
.wrap{{max-width:900px;margin:0 auto;padding:24px}}
h1{{font-size:20px;margin:0 0 4px}}
.score{{font-size:40px;font-weight:700;color:{rc}}}
.sub{{color:#57606a;font-size:13px;margin-bottom:18px}}
.finding{{background:#fff;border:1px solid #d0d7de;border-radius:10px;padding:12px 14px;margin:10px 0}}
.fhead{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
.sev{{color:#fff;font-size:11px;font-weight:700;padding:2px 7px;border-radius:5px}}
.conf{{font-size:12px;font-weight:600}} .cat{{font-size:11px;color:#57606a;background:#eef1f4;padding:2px 6px;border-radius:5px}}
.meta code{{background:#eef1f4;padding:1px 5px;border-radius:4px;font-size:12px}}
.ev{{color:#57606a;font-size:13px;margin:4px 0}} .fix{{font-size:13px;margin-top:4px}}
.note{{color:#57606a;font-size:12px;margin-top:16px}}
</style></head><body><div class="wrap">
<h1>🛡️ AgentShield — MCP Config Security Report</h1>
<div class="sub">{html.escape(target)} · {now}</div>
<div class="score">{report.risk_score}/100 · {report.rating}</div>
<div class="sub">{report.servers_analyzed} server(s) · {len(report.confirmed)} confirmed ·
{len(report.indicators)} indicator(s) needing review</div>
{body}
<div class="note">⚠️ "indicator" findings are heuristic and must be manually confirmed.
AgentShield performs static analysis only; it does not execute the config or any server.</div>
</div></body></html>"""
