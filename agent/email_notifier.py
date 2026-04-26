import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def _severity_to_subject_prefix(severity: str) -> str:
    sev = (severity or "").lower()
    if sev in {"critical", "critique"}:
        return "Incident critique détecté"
    if sev == "high":
        return "Incident élevé détecté"
    if sev == "medium":
        return "Incident moyen détecté"
    return "Incident de sécurité détecté"


def _build_body(report: dict, system_name: str) -> str:
    technique_id = report.get("mitre_technique_id", "N/A")
    technique_name = report.get("mitre_technique_name", "N/A")
    explanation = report.get("explanation", "N/A")

    remediation_steps = report.get("remediation_steps", [])
    actions_lines = []
    for step in remediation_steps[:5]:
        priority = step.get("priority", "N/A")
        action = step.get("action", "N/A")
        actions_lines.append(f"- [{priority}] {action}")

    actions = "\n".join(actions_lines) if actions_lines else "- N/A"

    return (
        "Bonjour,\n\n"
        f"Un incident de sécurité a été détecté sur le système {system_name}.\n"
        f"Technique identifiée : {technique_id} ({technique_name})\n\n"
        "Résumé :\n"
        f"{explanation}\n\n"
        "Actions recommandées :\n"
        f"{actions}\n\n"
        "Veuillez consulter le rapport en pièce jointe.\n\n"
        "Cordialement,\n"
        "SOC Copilot\n"
    )


def send_incident_email(report: dict, pdf_path: Path, alert: dict) -> str:
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)
    smtp_to = (
        alert.get("extra", {}).get("email_to")
        or os.getenv("SOC_EMAIL_TO", "")
    )
    smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}

    if not smtp_host:
        return "skipped: SMTP_HOST not configured"
    if not smtp_from:
        return "skipped: SMTP_FROM/SMTP_USER not configured"
    if not smtp_to:
        return "skipped: recipient not configured (extra.email_to or SOC_EMAIL_TO)"
    if not pdf_path.exists():
        return f"failed: attachment not found: {pdf_path}"

    severity = str(report.get("severity", "")).lower()
    subject = _severity_to_subject_prefix(severity)
    system_name = alert.get("agent_name", "X")
    body = _build_body(report, system_name)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = smtp_to
    msg.set_content(body)

    with open(pdf_path, "rb") as f:
        content = f.read()
    msg.add_attachment(content, maintype="application", subtype="pdf", filename=pdf_path.name)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            if smtp_use_tls:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return f"sent to {smtp_to}"
    except Exception as exc:
        return f"failed: {exc}"
