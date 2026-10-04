from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from datetime import datetime
import os
from textwrap import wrap

def generate_report(
    workspace,
    case_id,
    investigator_name,
    investigator_id,
    organization,
    file_hashes,
    incident_type,
    incidents,
    timeline,
    risk_score,
    severity,
    narrative,
    ai_analysis=None
):
    report_path = os.path.join(workspace, "Forensic_Report.pdf")
    c = canvas.Canvas(report_path, pagesize=A4)
    width, height = A4

    x_margin = 2 * cm
    y = height - 2 * cm

    def heading(text):
        nonlocal y
        if y < 3 * cm:
            c.showPage()
            y = height - 2 * cm
        c.setFont("Helvetica-Bold", 14)
        c.drawString(x_margin, y, text)
        y -= 18

    def divider():
        nonlocal y
        c.line(x_margin, y, width - x_margin, y)
        y -= 14

    def body(text):
        nonlocal y
        c.setFont("Helvetica", 10)
        max_chars = 90

        lines = []
        for paragraph in text.split("\n"):
            lines.extend(wrap(paragraph, max_chars))
            lines.append("")

        for line in lines:
            if y < 2 * cm:
                c.showPage()
                y = height - 2 * cm
                c.setFont("Helvetica", 10)

            c.drawString(x_margin, y, line)
            y -= 12

    # ---------- TITLE PAGE ----------
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(
        width / 2,
        height - 5 * cm,
        "DIGITAL FORENSIC INVESTIGATION REPORT"
    )

    c.setFont("Helvetica", 12)
    c.drawCentredString(
        width / 2,
        height - 6.5 * cm,
        "ForensicLens – Automated Digital Forensics & Incident Analysis System"
    )

    c.setFont("Helvetica", 10)
    c.drawCentredString(width / 2, height - 8 * cm, f"Case ID: {case_id}")
    c.drawCentredString(
        width / 2,
        height - 9 * cm,
        f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )

    # ---------- CHAIN OF CUSTODY PAGE ----------
    c.showPage()
    y = height - 2 * cm

    heading("Chain of Custody & Investigator Details")
    divider()

    body(
        f"Case Number           : {case_id}\n"
        f"Investigator Name     : {investigator_name}\n"
        f"Investigator ID       : {investigator_id}\n"
        f"Organization          : {organization}\n"
        f"Tool Used             : ForensicLens – Automated Digital Forensics System\n"
        f"Date of Acquisition   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )

    body(
        "Evidence Handling Statement:\n"
        "The digital evidence associated with this investigation was collected, "
        "processed, and analyzed in a controlled, read-only manner. All uploaded "
        "log files were handled temporarily within an isolated workspace. No evidence "
        "or derived artifacts were retained after report generation. Cryptographic "
        "hashing (SHA-256) was applied to ensure evidence integrity and tamper detection."
    )

    # ---------- CASE SUMMARY ----------
    c.showPage()
    y = height - 2 * cm

    heading("1. Case Summary")
    divider()
    body(
        f"Incident Classification : {incident_type}\n"
        f"Risk Score             : {risk_score}\n"
        f"Severity Level         : {severity}"
    )

    # ---------- EVIDENCE INTEGRITY ----------
    heading("2. Evidence Integrity Verification")
    divider()
    body(
        "The integrity of the uploaded digital evidence was verified using "
        "cryptographic SHA-256 hashing. The calculated hashes are listed below:"
    )

    for fname, h in file_hashes.items():
        body(f"{fname} : {h}")

    # ---------- ATTACK INDICATORS ----------
    heading("3. Detected Attack Indicators")
    divider()

    if incidents:
        for a in incidents:
            body(f"- {a}")
    else:
        body("No explicit attack indicators were detected during analysis.")

    # ---------- FORENSIC TIMELINE ----------
    heading("4. Reconstructed Incident Timeline")
    divider()

    for e in timeline:
        body(f"{e['timestamp']} | {e['type']} | {e['raw']}")

    # ---------- ANALYST NARRATIVE ----------
    heading("5. Analyst Narrative")
    divider()
    body(narrative)

    # ---------- CONCLUSION ----------
    heading("6. Conclusion")
    divider()
    body(
        "Based on the correlated analysis of multiple log sources, the observed "
        "activities indicate a potential security incident. The findings suggest "
        "abnormal system behavior that warrants further investigation and "
        "appropriate incident response measures."
    )

    # ---------- PRIVACY ----------
    heading("7. Privacy & Evidence Handling")
    divider()
    body(
        "ForensicLens follows a stateless, privacy-preserving design. All uploaded "
        "evidence was processed temporarily and securely deleted after analysis. "
        "This approach ensures confidentiality, ethical compliance, and data "
        "protection."
    )

    # ---------- AI ANALYSIS (IF PRESENT) ----------
    if ai_analysis:
        c.showPage()
        y = height - 2 * cm
        heading("8. AI-Assisted Analysis")
        divider()
        body(
            "AI-ASSISTED ANALYSIS\n\n"
            "This section contains AI-generated interpretation based on the structured "
            "forensic evidence available at the time of analysis.\n"
            "The underlying evidence remains authoritative."
        )
        
        if "explain_incident" in ai_analysis:
            exp = ai_analysis["explain_incident"]
            c.setFont("Helvetica-Bold", 12)
            c.drawString(x_margin, y, "AI Scenario Assessment")
            y -= 14
            body(exp.get("executive_summary", ""))
            
            if "key_findings" in exp:
                c.setFont("Helvetica-Bold", 12)
                c.drawString(x_margin, y, "AI Key Findings")
                y -= 14
                for f in exp["key_findings"]:
                    body(f"- {f.get('finding', '')}: {f.get('reason', '')}")
                    
        if "next_investigation" in ai_analysis:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(x_margin, y, "AI Recommended Investigation Steps")
            y -= 14
            for s in ai_analysis["next_investigation"].get("next_investigation_steps", []):
                body(f"- {s.get('step', '')}: {s.get('reason', '')}")

    c.save()
    return report_path
