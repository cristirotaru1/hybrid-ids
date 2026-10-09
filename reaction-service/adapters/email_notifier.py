"""Send operator alert notifications through SMTP."""

import logging
import smtplib
from html import escape
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from reaction_common import PendingAction

logger = logging.getLogger(__name__)


class EmailNotifier:
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        from_addr: str,
        to_addr: str,
        confirm_base_url: str,
        use_tls: bool = True,
    ):
        self._host = smtp_host
        self._port = smtp_port
        self._user = smtp_user
        self._password = smtp_password
        self._from = from_addr
        self._to = to_addr
        self._confirm_base_url = confirm_base_url.rstrip("/")
        self._use_tls = use_tls

    def notify(self, pending: PendingAction, token: str) -> bool:
        """Send an alert email and report whether delivery succeeded."""
        confirm_url = f"{self._confirm_base_url}/react/confirm/{token}"

        subject = f"[NIDS] Priority-{pending.priority} alert: {pending.msg}"

        text_body = self._build_text_body(pending, confirm_url)
        html_body = self._build_html_body(pending, confirm_url)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._from
        msg["To"] = self._to
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self._host, self._port, timeout=10) as server:
                if self._use_tls:
                    server.starttls()
                if self._user:
                    server.login(self._user, self._password)
                server.sendmail(self._from, [self._to], msg.as_string())
            logger.info("Alert email sent for sid=%d pending_id=%d", pending.sid, pending.id)
            return True
        except (smtplib.SMTPException, OSError) as exc:
            logger.error("Failed to send alert email for sid=%d: %s", pending.sid, exc)
            return False

    def _build_text_body(self, pending: PendingAction, confirm_url: str) -> str:
        return (
            f"A priority-{pending.priority} Snort alert was triggered.\n\n"
            f"Signature: {pending.msg} (sid={pending.sid})\n"
            f"Protocol:  {pending.proto}\n"
            f"Source:    {pending.src_addr}:{pending.src_port}\n"
            f"Dest:      {pending.dst_addr}:{pending.dst_port}\n"
            f"Time:      {pending.alert_ts}\n\n"
            f"This link expires at {pending.expires_at}.\n"
            f"Review and confirm action here:\n{confirm_url}\n"
        )

    def _build_html_body(self, pending: PendingAction, confirm_url: str) -> str:
        msg = escape(pending.msg)
        proto = escape(pending.proto)
        src_addr = escape(pending.src_addr)
        dst_addr = escape(pending.dst_addr)
        return f"""
        <html>
          <body style="font-family: Arial, sans-serif; color: #222;">
            <h2 style="color: #b00020;">Priority-{pending.priority} Snort Alert</h2>
            <table cellpadding="6" style="border-collapse: collapse;">
              <tr><td><b>Signature</b></td><td>{msg} (sid={pending.sid})</td></tr>
              <tr><td><b>Protocol</b></td><td>{proto}</td></tr>
              <tr><td><b>Source</b></td><td>{src_addr}:{pending.src_port}</td></tr>
              <tr><td><b>Destination</b></td><td>{dst_addr}:{pending.dst_port}</td></tr>
              <tr><td><b>Time</b></td><td>{pending.alert_ts}</td></tr>
            </table>
            <p>
              <a href="{confirm_url}"
                 style="display:inline-block; padding:10px 18px; background:#b00020;
                        color:#fff; text-decoration:none; border-radius:4px;">
                Review Alert &amp; Block Traffic
              </a>
            </p>
            <p style="color:#666; font-size:12px;">
              This link expires at {pending.expires_at}. If this looks like a
              false positive, you can simply ignore this email.
            </p>
          </body>
        </html>
        """
