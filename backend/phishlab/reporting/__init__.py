"""Report generation: JSON (versioned schema) and PDF. URLs defanged by default.

The JSON schema is versioned (REPORT_SCHEMA_VERSION) and documented in
docs/report-schema.md. PDF is produced with reportlab (pure-Python, offline).
"""

from __future__ import annotations

import io
import re
from datetime import UTC, datetime

REPORT_SCHEMA_VERSION = "1.0"

_EMAILISH = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _redact_text(text: str | None) -> str | None:
    if not text:
        return text
    return _EMAILISH.sub("[redacted-email]", text)


def build_json_report(case: dict, redact: bool = True) -> dict:
    analysis = case.get("analysis", {})
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "redacted": redact,
        "case": {
            "id": case.get("id"),
            "created_at": case.get("created_at"),
            "disposition": case.get("disposition", "undetermined"),
            "rationale": case.get("rationale"),
            "analyst_notes": _redact_text(case.get("notes")) if redact else case.get("notes"),
        },
        "artifact": analysis.get("artifact", {}),
        "sender_analysis": analysis.get("summary_headers", {}),
        "authentication": analysis.get("auth", {}),
        "indicators": analysis.get("indicators", {}),  # already defanged
        "attachments": analysis.get("attachments", []),
        "findings": analysis.get("findings", []),
        "assessment": analysis.get("assessment", {}),
        "warnings": analysis.get("warnings", []),
        "caveats": [
            "Authentication results are sender-reported and not independently verified.",
            "Static file-type detection uses magic bytes and can be spoofed.",
            "Absence of findings is not proof of safety.",
            "URLs are defanged; never visit them directly.",
        ],
    }
    if redact:
        sa = report["sender_analysis"]
        for k in ("from", "to", "reply_to", "return_path"):
            if sa.get(k):
                sa[k] = _redact_text(sa[k])
    return report


def build_pdf_report(case: dict, redact: bool = True) -> bytes:
    # Imported lazily so the rest of the app works even if reportlab is absent.
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    rpt = build_json_report(case, redact=redact)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        title="PhishLab Investigation Report",
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle("Mono", parent=styles["Normal"], fontName="Courier", fontSize=8, leading=10)
    )
    h2 = ParagraphStyle("H2b", parent=styles["Heading2"], textColor=colors.HexColor("#1f2d3d"))
    small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, textColor=colors.grey)

    sev_color = {
        "critical": colors.HexColor("#7f1d1d"),
        "high": colors.HexColor("#b91c1c"),
        "medium": colors.HexColor("#b45309"),
        "low": colors.HexColor("#2563eb"),
        "informational": colors.grey,
    }

    def esc(s) -> str:
        return (
            (str(s) if s is not None else "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    story = []
    story.append(Paragraph("PhishLab Investigation Report", styles["Title"]))
    story.append(
        Paragraph(
            f"Schema v{rpt['schema_version']} · generated {rpt['generated_at']} · "
            f"{'redacted' if redact else 'unredacted'}",
            small,
        )
    )
    story.append(HRFlowable(width="100%", color=colors.lightgrey))
    story.append(Spacer(1, 6))

    assess = rpt["assessment"]
    story.append(Paragraph("Executive summary", h2))
    story.append(Paragraph(esc(assess.get("summary", "")), styles["Normal"]))
    story.append(
        Paragraph(
            f"Disposition: <b>{esc(rpt['case']['disposition'])}</b> · "
            f"Highest severity: <b>{esc(assess.get('highest_severity'))}</b>",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 8))

    # Case + artifact
    art = rpt["artifact"]
    meta = [
        ["Case ID", esc(rpt["case"]["id"])],
        ["Created", esc(rpt["case"]["created_at"])],
        ["Artifact SHA-256", esc(art.get("sha256"))],
        ["Size (bytes)", esc(art.get("size"))],
        ["Source", esc(art.get("source_kind"))],
    ]
    t = Table(meta, colWidths=[40 * mm, 130 * mm])
    t.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 8))

    # Sender + auth
    sa = rpt["sender_analysis"]
    au = rpt["authentication"]
    story.append(Paragraph("Sender &amp; authentication", h2))
    sender_rows = [
        ["From", esc(sa.get("from"))],
        ["Reply-To", esc(sa.get("reply_to"))],
        ["Return-Path", esc(sa.get("return_path"))],
        ["Subject", esc(sa.get("subject"))],
        ["SPF (reported)", esc(au.get("spf"))],
        ["DKIM (reported)", esc(au.get("dkim"))],
        ["DMARC (reported)", esc(au.get("dmarc"))],
    ]
    t = Table(sender_rows, colWidths=[40 * mm, 130 * mm])
    t.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(t)
    story.append(Paragraph("Authentication results are sender-reported, not verified.", small))
    story.append(Spacer(1, 8))

    # Findings
    story.append(Paragraph(f"Findings ({len(rpt['findings'])})", h2))
    for f in rpt["findings"]:
        sc = sev_color.get(f.get("severity", "informational"), colors.grey)
        story.append(
            Paragraph(
                f'<font color="{sc.hexval()}"><b>[{esc(f.get("severity")).upper()}]</b></font> '
                f"{esc(f.get('rule_id'))} - {esc(f.get('title'))} "
                f'<font size=7 color="grey">(confidence: {esc(f.get("confidence"))})</font>',
                styles["Normal"],
            )
        )
        story.append(Paragraph(f"Evidence: {esc(f.get('evidence'))}", styles["Mono"]))
        story.append(Paragraph(esc(f.get("explanation")), small))
        story.append(Paragraph(f"→ {esc(f.get('recommendation'))}", small))
        story.append(Spacer(1, 4))
    if not rpt["findings"]:
        story.append(Paragraph("No findings produced by static analysis.", styles["Normal"]))

    # Indicators (defanged)
    story.append(Spacer(1, 6))
    story.append(Paragraph("Indicators (defanged)", h2))
    for u in rpt["indicators"].get("urls", [])[:50]:
        story.append(Paragraph(esc(u.get("defanged")), styles["Mono"]))
    story.append(Spacer(1, 8))

    # Caveats
    story.append(Paragraph("Limitations &amp; caveats", h2))
    for c in rpt["caveats"]:
        story.append(Paragraph("• " + esc(c), small))

    doc.build(story)
    return buf.getvalue()
