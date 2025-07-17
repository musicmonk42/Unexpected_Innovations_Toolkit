# upm/notifications.py

import smtplib
import ssl
import sys
import re
from enum import Enum, auto
import os
from email.mime.text import MIMEText
from typing import Dict, Any, Optional
import logging

# For retry logic
try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, Retrying
    _TENACITY_AVAILABLE = True
except ImportError:
    _TENACITY_AVAILABLE = False
    sys.stderr.write("Warning: 'tenacity' not installed. Notification sending will not have retry logic.\n")

# --- Conditional Imports for External Libraries ---
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    import slack_sdk
    from slack_sdk.errors import SlackApiError
    _SLACK_SDK_AVAILABLE = True
except ImportError:
    slack_sdk = None
    SlackApiError = None
    _SLACK_SDK_AVAILABLE = False

# --- Import from other UPM modules ---
from upm.logging_utils import AUDIT_LOGGER, log_audit, AuditOperation, redact_secrets

# --- Constants and Enums ---
COMMON_SMTP_PORTS = [587, 465, 25]
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
SLACK_CHANNEL_REGEX = re.compile(r"^(#|C)[A-Z0-9]{1,20}$", re.IGNORECASE)
HOSTNAME_REGEX = re.compile(r"^(localhost|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$")


class NotificationEvent(Enum):
    """Defines standardized event types for notifications."""
    OPERATION_SUCCESS = auto()
    OPERATION_FAILURE = auto()
    SECURITY_ALERT = auto()
    HEALTH_WARNING = auto()

class Notifier:
    """
    Handles sending various types of notifications (e.g., email, Slack).
    Applies input redaction, retry logic, robust configuration validation,
    and provides clear, human-readable error messages with console fallbacks.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config: Dict[str, Any] = config.get("notifications", {})

    def _alert_user_on_failure(self, service: str, error_detail: str, verbose: bool):
        """Helper to alert the user directly on the console if a notification fails."""
        raw_msg = f"Failed to send {service} notification. {error_detail}"
        sys.stderr.write(f"❌ Notifier Warning: {redact_secrets(raw_msg)}\n")
        log_audit(logging.ERROR, redact_secrets(raw_msg), operation=AuditOperation.NOTIFICATION, context={"service": service})

    def _validate_email_config(self, config: Dict[str, Any]) -> bool:
        """Validates email configuration fields."""
        if not config.get("enabled", False): return False
        use_auth = config.get("use_auth", True)
        password_required = os.environ.get("UPM_EMAIL_PASSWORD") if use_auth else True
        sender, recipient, smtp_server = config.get("sender"), config.get("recipient"), config.get("smtp_server")
        
        if not all([sender, recipient, smtp_server, password_required]):
            self._alert_user_on_failure("Email", "Incomplete config. Ensure sender, recipient, smtp_server, and UPM_EMAIL_PASSWORD env var (if auth is enabled) are set.", False)
            return False
        if not (EMAIL_REGEX.fullmatch(sender) and EMAIL_REGEX.fullmatch(recipient) and smtp_server and HOSTNAME_REGEX.fullmatch(smtp_server)):
            self._alert_user_on_failure("Email", "Invalid format for sender, recipient, or SMTP server.", False)
            return False
        return True

    def _validate_slack_config(self, config: Dict[str, Any]) -> bool:
        """Validates Slack configuration fields."""
        if not config.get("enabled", False): return False
        webhook_url, token = config.get("webhook_url"), os.environ.get("UPM_SLACK_TOKEN")
        if not (webhook_url or token):
            self._alert_user_on_failure("Slack", "Incomplete config: Neither webhook_url nor UPM_SLACK_TOKEN env var is set.", False)
            return False
        return True

    def _send_email_attempt(self, sender: str, recipient: str, smtp_server: str, port: int, password: str, msg_as_string: str, use_tls: bool, use_auth: bool):
        """Internal helper to attempt sending an email for retry logic."""
        context = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(smtp_server, port, timeout=10, context=context) as server:
                if use_auth: server.login(sender, password)
                server.sendmail(sender, recipient, msg_as_string)
        else:
            with smtplib.SMTP(smtp_server, port, timeout=10) as server:
                if use_tls and port != 25:
                    server.starttls(context=context)
                if use_auth: server.login(sender, password)
                server.sendmail(sender, recipient, msg_as_string)

    def send_email(self, subject: str, body: str, verbose: bool = False):
        """Sends an email notification with retry logic across multiple common ports."""
        email_config = self.config.get("email", {})
        if not self._validate_email_config(email_config): return

        sender, recipient, smtp_server = email_config["sender"], email_config["recipient"], email_config["smtp_server"]
        use_tls = email_config.get("use_tls", True)
        use_auth = email_config.get("use_auth", True)
        password = os.environ.get("UPM_EMAIL_PASSWORD") if use_auth else ""
        
        msg = MIMEText(redact_secrets(body))
        msg["Subject"], msg["From"], msg["To"] = redact_secrets(subject), sender, recipient

        ports_to_try = email_config.get("smtp_port", COMMON_SMTP_PORTS)
        if isinstance(ports_to_try, int): ports_to_try = [ports_to_try]

        final_exception = None
        for port in ports_to_try:
            try:
                action = lambda: self._send_email_attempt(sender, recipient, smtp_server, port, password, msg.as_string(), use_tls, use_auth)
                if _TENACITY_AVAILABLE:
                    retryer = Retrying(
                        stop=stop_after_attempt(3), wait=wait_exponential(max=10),
                        retry=retry_if_exception_type((smtplib.SMTPException, OSError)), reraise=True
                    )
                    retryer(action)
                else:
                    action()
                
                log_audit(logging.INFO, f"Email notification sent to {recipient} via port {port}.", operation=AuditOperation.NOTIFICATION)
                return
            except Exception as e:
                final_exception = e
        
        self._alert_user_on_failure("Email", f"All attempts failed. Last error: {final_exception}", verbose)

    def _send_slack_webhook(self, webhook_url: str, text_message: str):
        """Sends a message to a Slack webhook."""
        if not _REQUESTS_AVAILABLE: raise RuntimeError("Missing 'requests' for Slack webhook.")
        response = requests.post(webhook_url, json={"text": text_message}, timeout=15)
        response.raise_for_status()

    def _send_slack_sdk(self, token: str, channel: str, text_message: str):
        """Sends a message using the Slack SDK."""
        if not _SLACK_SDK_AVAILABLE: raise RuntimeError("Missing 'slack_sdk' for Slack WebClient.")
        client = slack_sdk.WebClient(token=token)
        client.chat_postMessage(channel=channel, text=text_message)

    def send_slack(self, message: str, verbose: bool = False):
        """Sends a Slack notification, preferring a bot token over a webhook."""
        slack_config = self.config.get("slack", {})
        if not self._validate_slack_config(slack_config): return

        redacted_message = redact_secrets(message)
        channel = slack_config.get("channel", "#general")
        token = os.environ.get("UPM_SLACK_TOKEN")
        webhook_url = slack_config.get("webhook_url")
        
        method, action = ("Direct Token", lambda: self._send_slack_sdk(token, channel, redacted_message)) if token else \
                         ("Webhook", lambda: self._send_slack_webhook(webhook_url, redacted_message))
        
        try:
            if _TENACITY_AVAILABLE:
                retryer = Retrying(
                    stop=stop_after_attempt(3), wait=wait_exponential(max=10),
                    retry=retry_if_exception_type((requests.exceptions.RequestException, SlackApiError if _SLACK_SDK_AVAILABLE else IOError)), reraise=True
                )
                for attempt in retryer:
                    with attempt: action()
            else:
                action()
            
            log_audit(logging.INFO, "Slack notification sent successfully.", operation=AuditOperation.NOTIFICATION, context={"method": method})
        except Exception as e:
            self._alert_user_on_failure("Slack", f"All attempts failed using method {method}. Error: {e}", verbose)