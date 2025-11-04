import os
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.utils import ImageReader
from recomendations import Recs


def logo (canvas_obj, doc, logo_path):
    if os.path.exists(logo_path):
        logo = ImageReader(logo_path)
        width, height = A4
        logo_width = 100
        logo_height = 100
        canvas_obj.drawImage(
            logo,
            width - logo_width - 30,
            height - logo_height - 50,
            width=logo_width,
            height=logo_height,
            mask='auto'
        )

def generate_pdf(results,pdf_path="WebSET_Report.pdf", sev_chart_path="severity_bar.png", threat_chart_path="threats_bar.png", logo_path="AppSecGuard.png", severity_chart_path=None ):
    if severity_chart_path:
        sev_chart_path = severity_chart_path
    style = getSampleStyleSheet()
    body = style["BodyText"]
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    story = []

    story.append(Paragraph("WebSET Scan Results", style["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Scan Results", style["Heading2"]))

    if os.path.exists(sev_chart_path):
        story.append(Image(sev_chart_path, width=420, height=250))
        story.append(Spacer(1, 8))
    if os.path.exists(threat_chart_path):
        story.append(Image(threat_chart_path, width=420, height=250))
        story.append(Spacer(1, 12))

    data = [["Threat", "Severity", "Message"]]
    for issue in results.get("issues", []):
        thrt = issue.get("Threat", "")
        sevrty = issue.get("Threat Severity", "")
        msg_text = (issue.get("Message", "") or "").replace("\n", " ")
        msg = Paragraph(msg_text, body)
        data.append([thrt, sevrty, msg])

    if len(data) == 1:
        data.append(["—", "—", "No issues found."])

    table = Table(data, colWidths=[160, 80, 260])
    table.setStyle([("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")])
    story.append(table)

    story.append(Spacer(1, 18))
    story.append(Paragraph("Recommendations", style["Heading2"]))
    story.append(Spacer(1, 6))

    for thr in Recs:
        if any(thr == iss.get("Threat") for iss in results.get("issues", [])):
            story.append(Paragraph(f"<b>{thr}</b>", style["Heading3"]))
            story.append(Paragraph(Recs[thr], style["BodyText"]))
            story.append(Spacer(1, 10))


    doc.build(story,
              onFirstPage=lambda c, d: logo(c, d, logo_path),
              onLaterPages=lambda c, d: logo(c, d, logo_path))
    print(f"PDF report saved to {pdf_path}")
