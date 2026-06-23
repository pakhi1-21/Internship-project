"""
NetSight - Email Alerts (MODULE 12)
==========================================
Optional email notification system for HIGH and CRITICAL severity alerts.
Sends formatted HTML emails via SMTP when triggered by the AlertManager.

Purpose:
    - Send email notifications for HIGH/CRITICAL alerts
    - Rate limiting to prevent email flooding
    - HTML formatted email templates
    - Configurable SMTP settings
    - Gracefully disabled when SMTP not configured

Configuration (in config.py):
    EMAIL_ENABLED = True
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 587
    SMTP_USE_TLS = True
    SMTP_USERNAME = 'your-email@gmail.com'
    SMTP_PASSWORD = 'your-app-password'
    EMAIL_FROM = 'your-email@gmail.com'
    EMAIL_RECIPIENTS = ['admin@example.com']
"""

import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from collections import defaultdict

from config import (
    EMAIL_ENABLED, SMTP_SERVER, SMTP_PORT, SMTP_USE_TLS,
    SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_RECIPIENTS,
    EMAIL_RATE_LIMIT, REPORT_COMPANY_NAME
)
from backend.logger import get_system_logger

logger = get_system_logger('EmailAlerts')


class EmailAlertSender:
    """
    Email notification sender for high-severity security alerts.

    Features rate limiting per alert type to prevent email flooding.
    Uses SMTP with TLS support.

    Attributes:
        _last_sent: Dict mapping alert_type → last send timestamp
        _lock: Thread lock for rate limit tracking
    """

    def __init__(self):
        """Initialize the EmailAlertSender."""
        self._last_sent = defaultdict(float)  # alert_type → timestamp
        self._lock = threading.Lock()
        self._enabled = EMAIL_ENABLED and SMTP_USERNAME and EMAIL_RECIPIENTS

        if self._enabled:
            logger.info('Email alerts enabled (server: %s, recipients: %d)',
                         SMTP_SERVER, len(EMAIL_RECIPIENTS))
        else:
            logger.info('Email alerts disabled (not configured)')

    def send_alert_email(self, alert_data):
        """
        Send an email notification for a security alert.

        Applies rate limiting: max one email per alert type within
        EMAIL_RATE_LIMIT seconds (default: 15 minutes).

        Args:
            alert_data: Dict with keys: alert_type, severity, source_ip,
                       description, details, timestamp
        """
        if not self._enabled:
            return

        alert_type = alert_data.get('alert_type', 'UNKNOWN')

        # Rate limiting check
        with self._lock:
            now = time.time()
            if now - self._last_sent[alert_type] < EMAIL_RATE_LIMIT:
                logger.debug('Email rate limited for alert type: %s', alert_type)
                return
            self._last_sent[alert_type] = now

        # Send in background thread to avoid blocking
        thread = threading.Thread(
            target=self._send_email,
            args=(alert_data,),
            daemon=True
        )
        thread.start()

    def _send_email(self, alert_data):
        """
        Internal method to send the email via SMTP.

        Args:
            alert_data: Dict with alert details
        """
        try:
            severity = alert_data.get('severity', 'HIGH')
            alert_type = alert_data.get('alert_type', 'UNKNOWN').replace('_', ' ')

            # Build email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = (
                f'[{REPORT_COMPANY_NAME}] {severity} Alert: {alert_type}'
            )
            msg['From'] = EMAIL_FROM
            msg['To'] = ', '.join(EMAIL_RECIPIENTS)

            # Plain text version
            text_body = (
                f'{REPORT_COMPANY_NAME} - Security Alert\n'
                f'{"=" * 50}\n\n'
                f'Severity: {severity}\n'
                f'Type: {alert_type}\n'
                f'Source IP: {alert_data.get("source_ip", "N/A")}\n'
                f'Time: {alert_data.get("timestamp", "N/A")}\n\n'
                f'Description: {alert_data.get("description", "N/A")}\n\n'
                f'Details: {alert_data.get("details", "N/A")}\n'
            )

            # HTML version
            severity_color = {
                'LOW': '#28a745',
                'MEDIUM': '#ffc107',
                'HIGH': '#fd7e14',
                'CRITICAL': '#dc3545'
            }.get(severity, '#6c757d')

            html_body = f'''
            <html>
            <body style="font-family: Arial, sans-serif; background-color: #0a0e17; color: #e0e0e0; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: #1a1f2e; border-radius: 10px; padding: 30px; border: 1px solid #2d3548;">
                    <h1 style="color: #00d4ff; margin-bottom: 5px;">{REPORT_COMPANY_NAME}</h1>
                    <p style="color: #8892a0; margin-top: 0;">Security Alert Notification</p>
                    <hr style="border-color: #2d3548;">

                    <div style="background: {severity_color}22; border-left: 4px solid {severity_color}; padding: 15px; margin: 15px 0; border-radius: 4px;">
                        <h2 style="color: {severity_color}; margin: 0 0 10px 0;">
                            ⚠ {severity} — {alert_type}
                        </h2>
                        <p style="margin: 5px 0;"><strong>Source IP:</strong> {alert_data.get("source_ip", "N/A")}</p>
                        <p style="margin: 5px 0;"><strong>Time:</strong> {alert_data.get("timestamp", "N/A")}</p>
                    </div>

                    <h3 style="color: #00d4ff;">Description</h3>
                    <p>{alert_data.get("description", "N/A")}</p>

                    <h3 style="color: #00d4ff;">Details</h3>
                    <p style="background: #0d1117; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 13px;">
                        {alert_data.get("details", "N/A")}
                    </p>

                    <hr style="border-color: #2d3548;">
                    <p style="color: #8892a0; font-size: 12px;">
                        This is an automated alert from {REPORT_COMPANY_NAME}.
                        Log in to the dashboard for full details.
                    </p>
                </div>
            </body>
            </html>
            '''

            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            # Send via SMTP
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                if SMTP_USE_TLS:
                    server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)

            logger.info('Alert email sent: %s %s to %d recipients',
                         severity, alert_type, len(EMAIL_RECIPIENTS))

        except smtplib.SMTPAuthenticationError:
            logger.error('SMTP authentication failed — check credentials')
        except smtplib.SMTPException as e:
            logger.error('SMTP error: %s', str(e))
        except Exception as e:
            logger.error('Email send failed: %s', str(e))


# ============================================================
# SINGLETON & CONVENIENCE FUNCTION
# ============================================================
_email_sender = EmailAlertSender()


def send_alert_email(alert_data):
    """
    Convenience function to send an alert email.
    Called by AlertManager when HIGH/CRITICAL alerts are created.

    Args:
        alert_data: Dict with alert details
    """
    _email_sender.send_alert_email(alert_data)
