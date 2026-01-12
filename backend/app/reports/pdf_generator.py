from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_bytes(report: dict) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elements = []

    title = "Dynamic Risk Management System Report"
    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Spacer(1, 12))
    meta = f"Generated at: {report.get('generated_at')}"
    elements.append(Paragraph(meta, styles["Normal"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(f"Overall Risk Score: {report.get('risk_score')}/100", styles["Heading2"]))
    elements.append(Paragraph(report.get("summary", ""), styles["Normal"]))
    elements.append(Spacer(1, 12))

    stats = [
        ["Rows processed", report.get("rows")],
        ["Mean score", f"{report.get('mean'):.2f}"],
        ["Max score", report.get("max")],
        ["Min score", report.get("min")],
    ]
    t = Table(stats, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(t)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Top Findings", styles["Heading3"]))
    findings = report.get("top_findings", [])
    if findings:
        for finding in findings:
            elements.append(Paragraph("- " + finding, styles["Normal"]))
    else:
        elements.append(Paragraph("No critical findings.", styles["Normal"]))

    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf
