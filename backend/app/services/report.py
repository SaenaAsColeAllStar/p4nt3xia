"""Report generation — JSON, HTML, Markdown, and PDF."""

from __future__ import annotations

import html
import io
from typing import Any

from sqlalchemy.orm import Session, joinedload

from app.models.finding import Finding
from app.models.scan import Scan


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def scan_to_json(db: Session, scan_id: str) -> dict[str, Any] | None:
    scan = (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan:
        return None
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.created_at.asc())
        .all()
    )
    severity_counts = _severity_counts(findings)
    duration = None
    if scan.started_at and scan.completed_at:
        duration = (scan.completed_at - scan.started_at).total_seconds()

    return {
        "scan_id": scan.id,
        "mode": scan.mode,
        "status": scan.status,
        "target": scan.target.value if scan.target else (scan.configuration or {}).get("target"),
        "configuration": {
            k: v
            for k, v in (scan.configuration or {}).items()
            if k != "auth_header"  # never leak credentials into exports
        },
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_seconds": duration,
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "type": f.finding_type,
                "description": f.description,
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
                "poc_request": f.poc_request,
                "poc_response": f.poc_response,
                "poc_curl": f.poc_curl,
                "remediation": f.remediation,
                "references": f.references or [],
            }
            for f in findings
        ],
    }


def scan_to_markdown(db: Session, scan_id: str) -> str | None:
    data = scan_to_json(db, scan_id)
    if not data:
        return None
    lines = [
        f"# P4NT3XIA Report — {data.get('target') or scan_id}",
        "",
        f"- **Mode:** {data.get('mode')}",
        f"- **Status:** {data.get('status')}",
        f"- **Started:** {data.get('started_at') or '—'}",
        f"- **Duration (s):** {data.get('duration_seconds') if data.get('duration_seconds') is not None else '—'}",
        f"- **Findings:** {data['summary']['total_findings']}",
        "",
        "## Severity breakdown",
        "",
    ]
    for sev, count in (data["summary"]["severity_breakdown"] or {}).items():
        lines.append(f"- {sev}: {count}")
    lines.extend(["", "## Findings", ""])
    for f in data["findings"]:
        lines.append(f"### [{(f.get('severity') or 'info').upper()}] {f.get('title')}")
        if f.get("cvss_score") is not None:
            lines.append(f"- CVSS: {f['cvss_score']}")
        if f.get("cve_id"):
            lines.append(f"- CVE: {f['cve_id']}")
        if f.get("description"):
            lines.append(f"\n{f['description']}\n")
        if f.get("poc_curl"):
            lines.append(f"```bash\n{f['poc_curl']}\n```")
        if f.get("remediation"):
            lines.append(f"**Remediation:** {f['remediation']}")
        lines.append("")
    return "\n".join(lines)


def scan_to_pdf(db: Session, scan_id: str) -> bytes | None:
    """Executive + technical PDF via reportlab."""
    data = scan_to_json(db, scan_id)
    if not data:
        return None

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError(
            "PDF export requires reportlab. Install with: pip install reportlab"
        ) from exc

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"P4NT3XIA — {data.get('target') or scan_id}",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleP4",
        parent=styles["Title"],
        fontSize=18,
        textColor=colors.HexColor("#1e2a3a"),
        spaceAfter=6,
        alignment=TA_LEFT,
    )
    h2 = ParagraphStyle(
        "H2P4",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#0d7377"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body = ParagraphStyle(
        "BodyP4",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#1e2a3a"),
    )
    mono = ParagraphStyle(
        "MonoP4",
        parent=styles["Code"],
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0f1720"),
        backColor=colors.HexColor("#f4f7fb"),
    )

    def esc(text: object) -> str:
        return html.escape(str(text or "")).replace("\n", "<br/>")

    story: list[Any] = []
    story.append(Paragraph("P4NT3XIA Report", title_style))
    story.append(
        Paragraph(
            f"<b>Target:</b> {esc(data.get('target'))} &nbsp;|&nbsp; "
            f"<b>Mode:</b> {esc(data.get('mode'))} &nbsp;|&nbsp; "
            f"<b>Status:</b> {esc(data.get('status'))}",
            body,
        )
    )
    story.append(
        Paragraph(
            f"Scan {esc(data.get('scan_id'))} · started {esc(data.get('started_at'))} · "
            f"duration {esc(data.get('duration_seconds'))}s",
            body,
        )
    )
    story.append(Spacer(1, 8))

    story.append(Paragraph("Executive summary", h2))
    breakdown = data["summary"]["severity_breakdown"] or {}
    sev_order = ["critical", "high", "medium", "low", "info"]
    table_data = [["Severity", "Count"]]
    for s in sev_order:
        if breakdown.get(s):
            table_data.append([s, str(breakdown[s])])
    if len(table_data) == 1:
        table_data.append(["—", "0"])
    table_data.append(["Total", str(data["summary"]["total_findings"])])
    tbl = Table(table_data, colWidths=[80 * mm, 40 * mm])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2a3a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d8e0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fb")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(tbl)

    story.append(Paragraph("Technical findings", h2))
    if not data["findings"]:
        story.append(Paragraph("No findings.", body))
    for f in data["findings"]:
        story.append(
            Paragraph(
                f"<b>[{esc((f.get('severity') or 'info').upper())}]</b> "
                f"{esc(f.get('title'))} "
                f"(CVSS {esc(f.get('cvss_score') if f.get('cvss_score') is not None else '—')})",
                body,
            )
        )
        if f.get("cve_id"):
            story.append(Paragraph(f"CVE: {esc(f['cve_id'])}", body))
        if f.get("description"):
            story.append(Paragraph(esc(f["description"]), body))
        if f.get("poc_curl"):
            story.append(Paragraph(f"<font face='Courier'>{esc(f['poc_curl'])}</font>", mono))
        if f.get("remediation"):
            story.append(Paragraph(f"<b>Remediation:</b> {esc(f['remediation'])}", body))
        story.append(Spacer(1, 6))

    doc.build(story)
    return buf.getvalue()


def scan_to_html(db: Session, scan_id: str) -> str | None:
    data = scan_to_json(db, scan_id)
    if not data:
        return None

    sev_order = ["critical", "high", "medium", "low", "info"]
    breakdown = data["summary"]["severity_breakdown"]
    breakdown_rows = "".join(
        f"<tr><td>{html.escape(s)}</td><td>{breakdown.get(s, 0)}</td></tr>"
        for s in sev_order
        if breakdown.get(s)
    ) or "<tr><td colspan='2'>None</td></tr>"

    finding_blocks: list[str] = []
    for f in data["findings"]:
        refs = "".join(
            f'<li><a href="{html.escape(r)}" rel="noopener noreferrer">{html.escape(r)}</a></li>'
            for r in (f.get("references") or [])
            if isinstance(r, str)
        )
        poc_curl = html.escape(f.get("poc_curl") or "")
        poc_req = html.escape(f.get("poc_request") or "")
        poc_resp = html.escape(f.get("poc_response") or "")
        finding_blocks.append(
            f"""
<article class="finding sev-{html.escape(f.get('severity') or 'info')}" id="finding-{html.escape(f.get('id') or '')}">
  <header>
    <span class="badge">{html.escape((f.get('severity') or 'info').upper())}</span>
    <span class="cvss">CVSS {html.escape(str(f.get('cvss_score') if f.get('cvss_score') is not None else '—'))}</span>
    <h3>{html.escape(f.get('title') or 'Finding')}</h3>
  </header>
  <p class="meta"><strong>Type:</strong> {html.escape(f.get('type') or '')}
  {" · <strong>CVE:</strong> " + html.escape(f['cve_id']) if f.get('cve_id') else ""}</p>
  <p>{html.escape(f.get('description') or '')}</p>
  {f'<pre class="poc"><code>{poc_req}</code></pre>' if poc_req else ''}
  {f'<pre class="poc"><code>{poc_resp}</code></pre>' if poc_resp else ''}
  {f'<pre class="curl"><code>{poc_curl}</code></pre>' if poc_curl else ''}
  {f'<p><strong>Remediation:</strong> {html.escape(f.get("remediation") or "")}</p>' if f.get('remediation') else ''}
  {f'<ul class="refs">{refs}</ul>' if refs else ''}
</article>
"""
        )

    findings_html = "\n".join(finding_blocks) or "<p>No findings.</p>"
    filter_buttons = "".join(
        f'<button type="button" data-filter="{s}" class="filter-btn">{s}</button>'
        for s in sev_order
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>P4NT3XIA Report — {html.escape(str(data.get('target') or scan_id))}</title>
  <style>
    :root {{ --ink:#1e2a3a; --fog:#f4f7fb; --signal:#0d7377; --crit:#9b1d20; --high:#c45c26; --med:#b08900; --low:#3d5a80; --info:#6c757d; }}
    body {{ margin:0; font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; color:var(--ink); background:linear-gradient(160deg,#e8eef5,#f7fafc 40%,#edf5f4); }}
    main {{ max-width:960px; margin:0 auto; padding:2rem 1.25rem 4rem; }}
    h1 {{ font-family:"IBM Plex Serif", Georgia, serif; font-size:2.25rem; margin:0 0 .25rem; }}
    .sub {{ font-family: ui-monospace, monospace; font-size:.75rem; letter-spacing:.08em; text-transform:uppercase; color:#5a6a7a; }}
    table {{ border-collapse:collapse; width:100%; margin:1rem 0 2rem; background:#fff; }}
    th, td {{ border:1px solid #d0d8e0; padding:.55rem .75rem; text-align:left; font-size:.9rem; }}
    th {{ background:var(--ink); color:#f4f7fb; font-family:ui-monospace,monospace; font-size:.7rem; letter-spacing:.06em; text-transform:uppercase; }}
    .filters {{ display:flex; flex-wrap:wrap; gap:.4rem; margin:1rem 0; }}
    .filter-btn {{ font-family:ui-monospace,monospace; font-size:.65rem; text-transform:uppercase; letter-spacing:.06em; border:1px solid #c5d0da; background:#fff; padding:.35rem .6rem; cursor:pointer; }}
    .filter-btn.active, .filter-btn:hover {{ border-color:var(--signal); color:var(--signal); }}
    .finding {{ background:#fff; border-left:4px solid var(--info); padding:1rem 1.1rem; margin:0 0 1rem; box-shadow:0 1px 0 rgba(30,42,58,.06); }}
    .finding.sev-critical {{ border-color:var(--crit); }}
    .finding.sev-high {{ border-color:var(--high); }}
    .finding.sev-medium {{ border-color:var(--med); }}
    .finding.sev-low {{ border-color:var(--low); }}
    .finding.hidden {{ display:none; }}
    .badge {{ font-family:ui-monospace,monospace; font-size:.65rem; letter-spacing:.05em; background:var(--ink); color:#fff; padding:.2rem .45rem; margin-right:.5rem; }}
    .cvss {{ font-family:ui-monospace,monospace; font-size:.75rem; color:#5a6a7a; }}
    h3 {{ display:inline; font-size:1.05rem; margin:0; }}
    pre {{ background:#0f1720; color:#e2e8f0; padding:.75rem; overflow:auto; font-size:.75rem; }}
    a {{ color:var(--signal); }}
  </style>
</head>
<body>
<main>
  <p class="sub">P4NT3XIA · {html.escape(str(data.get('mode') or ''))} report</p>
  <h1>{html.escape(str(data.get('target') or 'Target'))}</h1>
  <p class="sub">Scan {html.escape(str(data.get('scan_id')))} · {html.escape(str(data.get('status') or ''))}
  · started {html.escape(str(data.get('started_at') or '—'))}
  · duration {html.escape(str(data.get('duration_seconds') if data.get('duration_seconds') is not None else '—'))}s</p>

  <h2>Summary</h2>
  <p>Total findings: <strong>{data['summary']['total_findings']}</strong></p>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{breakdown_rows}</tbody>
  </table>

  <h2>Findings</h2>
  <div class="filters">
    <button type="button" data-filter="all" class="filter-btn active">all</button>
    {filter_buttons}
  </div>
  <div id="findings">{findings_html}</div>
</main>
<script>
document.querySelectorAll('.filter-btn').forEach(btn => {{
  btn.addEventListener('click', () => {{
    const f = btn.dataset.filter;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.finding').forEach(el => {{
      if (f === 'all') el.classList.remove('hidden');
      else el.classList.toggle('hidden', !el.classList.contains('sev-' + f));
    }});
  }});
}});
</script>
</body>
</html>
"""
