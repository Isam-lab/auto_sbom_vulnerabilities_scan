import smtplib
import os
from email.message import EmailMessage
from utils import decode_base64_env, log_error

SMTP_SERVER = decode_base64_env("SMTP_SERVER") or ""
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = decode_base64_env("SMTP_USERNAME")
SMTP_PASSWORD = decode_base64_env("SMTP_PASSWORD")

if not SMTP_SERVER:
    raise ValueError("SMTP_SERVER environment variable is not set or could not be decoded.")

def send_multiple_cpe_alert(component_name, version, cpe_list, report_file_path, recipient_email):
    print(f"[SMTP DEBUG] Sending final report to {recipient_email}")
    if not all([SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD, recipient_email]):
        print("[SMTP] Missing SMTP configuration or recipient address.")
        return

    msg = EmailMessage()
    msg['Subject'] = f"Action needed for {component_name} {version}"
    msg['From'] = SMTP_USERNAME
    msg['To'] = recipient_email

    body = (
        f"The component **{component_name} {version}** has multiple possible CPEs.\n\n"
        f"Please review the list and manually insert a valid CPE value in the SBOM.\n\n"
        f"Detected CPEs:\n" + "\n".join(f"- {cpe}" for cpe in cpe_list)
    )
    msg.set_content(body)

    if os.path.exists(report_file_path):
        with open(report_file_path, 'rb') as f:
            file_data = f.read()
            filename = os.path.basename(report_file_path)
            msg.add_attachment(file_data, maintype='text', subtype='plain', filename=filename)

    try:
        print(f"[DEBUG] Sending email to {recipient_email}")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME or "", SMTP_PASSWORD or "")
            server.send_message(msg)
    except Exception as e:
        print(f"[SMTP ERROR] Error sending email: {e}")
        log_error(f"SMTP error: {e}")

def send_final_report_email(
    project_name, version, report_file_path, recipient_email,
    html_issues, cpe_conflicts, malformed_error=None, redmine_error=None
):
    print(f"[SMTP DEBUG] Sending final report to {recipient_email}")
    if not all([SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD, recipient_email]):
        print("[SMTP] Missing SMTP configuration or recipient address.")
        return

    subject = f"SBOM Scan Report for {project_name} {version}"
    action_needed = bool(cpe_conflicts or malformed_error or redmine_error)
    if action_needed:
        subject = f"Action Needed: SBOM Scan Report for {project_name} {version}"

    body = "<h2>SBOM Scan Summary</h2>"

    if malformed_error:
        body += f"<p style='color:red'><strong>Malformed SBOM detected:</strong> {malformed_error}</p>"

    if redmine_error:
        body += f"<p style='color:red'><strong>Redmine project error:</strong> {redmine_error}</p>"

    if cpe_conflicts:
        body += "<p style='color:red'><strong>Action required:</strong> The following components have multiple possible CPEs and need manual review:</p><ul>"
        for comp in cpe_conflicts:
            body += f"<li><strong>{comp}</strong></li>"
        body += "</ul>"

    if not action_needed:
        body += "<p><strong>No action required.</strong> All components were processed automatically.</p>"

    if html_issues:
        body += "<h3>Redmine Issue Summary:</h3>"
        for issue_html in html_issues:
            body += issue_html

    body += "<p>The full technical report is attached.</p>"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_USERNAME
    msg["To"] = recipient_email
    msg.add_alternative(body, subtype="html")

    if os.path.exists(report_file_path):
        with open(report_file_path, 'rb') as f:
            file_data = f.read()
            filename = os.path.basename(report_file_path)
            msg.add_attachment(file_data, maintype='text', subtype='plain', filename=filename)

    try:
        print(f"[SMTP DEBUG] Connecting to {SMTP_SERVER}:{SMTP_PORT}")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            try:
                server.login(SMTP_USERNAME or "", SMTP_PASSWORD or "")
            except smtplib.SMTPException as auth_error:
                print(f"[SMTP WARNING] Auth not supported – continuing without login: {auth_error}")
            server.send_message(msg)
            print(f"[SMTP] Final report sent to {recipient_email}")
    except Exception as e:
        print(f"[SMTP ERROR] Error sending final report: {e}")
        log_error(f"SMTP final report error: {e}")
