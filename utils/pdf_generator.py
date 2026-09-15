"""PDF report generator using ReportLab."""
from __future__ import annotations
from datetime import datetime
from typing import Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Preformatted,
)
from config import REPORT_DIR, SEVERITY_COLORS

STYLES = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=STYLES["Heading1"], fontSize=22, spaceAfter=12)
H2 = ParagraphStyle("H2", parent=STYLES["Heading2"], fontSize=16, spaceAfter=8)
BODY = ParagraphStyle("BODY", parent=STYLES["BodyText"], fontSize=10, leading=14)
MONO = ParagraphStyle("MONO", parent=STYLES["Code"], fontSize=8, leading=10)

def _sev_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#666666")
    return f'<font color="{color}"><b>{sev.upper()}</b></font>'

def build_pdf(
    target: str,
    executive_summary: str,
    vulnerabilities: list[dict[str, Any]],
    poc_results: list[dict[str, Any]],
    recon_data: dict[str, Any],
) -> str:
    safe = target.replace("/", "_").replace(":", "_").replace(" ", "_")
    out_path = REPORT_DIR / f"bug_report_{safe}_{datetime.utcnow():%Y%m%d_%H%M%S}.pdf"

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm,
        title=f"Bug Hunter Report — {target}",
        author="Bug Hunter Multi-AI",
    )
    story: list = []

    story.append(Paragraph("Bug Hunter Multi-AI", H1))
    story.append(Paragraph("Security Assessment Report", H2))
    story.append(Spacer(1, 0.5*cm))
    cover = [
        ["Target:", target],
        ["Generated:", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Classification:", "CONFIDENTIAL"],
        ["Tool:", "Bug Hunter Multi-AI (Groq + LangGraph)"],
    ]
    t = Table(cover, colWidths=[4*cm, 12*cm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LINEBELOW", (0,0), (-1,-1), 0.25, colors.lightgrey),
    ]))
    story.append(t)
    story.append(PageBreak())

    story.append(Paragraph("1. Executive Summary", H2))
    story.append(Paragraph(executive_summary or "No summary generated.", BODY))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("2. Findings Overview", H2))
    if vulnerabilities:
        rows = [["#", "Severity", "Type", "Endpoint"]]
        for i, v in enumerate(vulnerabilities, 1):
            rows.append([
                str(i),
                Paragraph(_sev_badge(v.get("severity", "Info")), BODY),
                Paragraph(v.get("type", "N/A"), BODY),
                Paragraph(v.get("endpoint", "N/A"), BODY),
            ])
        ft = Table(rows, colWidths=[1*cm, 2.5*cm, 5*cm, 7.5*cm])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#263238")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F5F5F5")]),
        ]))
        story.append(ft)
    else:
        story.append(Paragraph("No vulnerabilities detected.", BODY))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("3. Detailed Findings", H2))
    poc_map = {p.get("vuln_id"): p for p in poc_results}
    for i, v in enumerate(vulnerabilities, 1):
        story.append(Paragraph(
            f"3.{i} {v.get('type','Vulnerability')} — {_sev_badge(v.get('severity','Info'))}",
            BODY,
        ))
        story.append(Paragraph(f"<b>Endpoint:</b> {v.get('endpoint','N/A')}", BODY))
        story.append(Paragraph(f"<b>CVSS:</b> {v.get('cvss','N/A')}  <b>CVE:</b> {v.get('cve_ref','N/A')}", BODY))
        story.append(Paragraph(f"<b>Description:</b> {v.get('description','N/A')}", BODY))
        story.append(Paragraph(f"<b>Evidence:</b> {v.get('evidence','N/A')}", BODY))
        story.append(Paragraph(f"<b>Remediation:</b> {v.get('remediation','Apply vendor patch.')}", BODY))
        poc = poc_map.get(v.get("vuln_id"))
        if poc:
            story.append(Paragraph("<b>Proof of Concept:</b>", BODY))
            story.append(Preformatted(
                f"Steps: {poc.get('poc_steps','N/A')}\n"
                f"Payload: {poc.get('payload_used','N/A')}\n"
                f"Response: {poc.get('response_evidence','N/A')}\n"
                f"Status: {'PROVEN' if poc.get('exploitation_success') else 'INCONCLUSIVE'}",
                MONO,
            ))
        story.append(Spacer(1, 0.3*cm))
    story.append(PageBreak())

    story.append(Paragraph("4. Appendix — Raw Recon Data", H2))
    story.append(Preformatted(str(recon_data)[:8000], MONO))

    doc.build(story)
    return str(out_path)
