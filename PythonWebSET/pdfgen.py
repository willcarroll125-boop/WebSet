from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf(results, pdf_path="WebSET_Report.pdf", severity_chart_path=None, threat_chart_path=None):
    style = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    story = []

    story.append(Paragraph("WebSET Scan Results", style["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Scan Results", style["Heading2"]))

    # Add severity chart if provided
    if severity_chart_path:
        story.append(Image(severity_chart_path, width=420, height=250))
        story.append(Spacer(1, 8))
    if threat_chart_path and os.path.exists(threat_chart_path):
        story.append(Image(threat_chart_path, width=420, height=250))
        story.append(Spacer(1, 12))

    # --- Table data ---
    data = [["Threat", "Severity", "Message"]]
    for issue in results.get("issues", []):
        thrt = issue.get("Threat", "")
        sevrty = issue.get("Threat Severity", "")
        msg = (issue.get("Message", "") or "").replace("\n", " ")
        if len(msg) > 140:
            msg = msg[:137] + "..."
        data.append([thrt, sevrty, msg])

    if len(data) == 1:
        data.append(["—", "—", "No issues found."])

    table = Table(data, colWidths=[180, 100, 240])
    story.append(table)

    # --- Build PDF ---
    doc.build(story)
    print(f"PDF report saved to {pdf_path}")
