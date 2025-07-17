# upm/tests/test_notifications.py

import pytest
import os
import sys
import smtplib
import threading
import smtpd
import asyncore
from unittest.mock import MagicMock, patch
from email import message_from_string, policy, message_from_bytes
from email.message import EmailMessage

# UPM module imports
from upm.notifications import Notifier
from upm.logging_utils import AUDIT_LOGGER

# Conditional imports for mocking
try:
    import requests
    import slack_sdk
except ImportError:
    requests = None
    slack_sdk = None

# --- Fixtures ---

@pytest.fixture
def mock_smtplib_smtp():
    """Mocks smtplib.SMTP for isolated email sending tests."""
    with patch('smtplib.SMTP', autospec=True) as mock_smtp_class:
        yield mock_smtp_class

@pytest.fixture
def mock_slack_sdk_webclient():
    """Mocks slack_sdk.WebClient for isolated Slack token-based tests."""
    if not slack_sdk:
        pytest.skip("slack_sdk not installed")
    with patch('slack_sdk.WebClient', autospec=True) as mock_webclient_class:
        yield mock_webclient_class.return_value

@pytest.fixture
def notifier(monkeypatch):
    """Provides a Notifier instance with mocked credentials and a basic config."""
    config = {
        "notifications": {
            "email": {"enabled": True, "sender": "test@example.com", "recipient": "user@example.com", "smtp_server": "smtp.example.com", "smtp_port": 587},
            "slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/services/T0000/B0000/XXXXXXXX"}
        }
    }
    monkeypatch.setenv("UPM_EMAIL_PASSWORD", "test_email_password")
    monkeypatch.setenv("UPM_SLACK_TOKEN", "xoxb-test-token")
    return Notifier(config)

# --- Unit Tests (Using Mocks) ---

class TestNotifierUnit:

    def test_send_email_success(self, notifier, mock_smtplib_smtp):
        """Verifies successful email sending and validates the MIME message."""
        notifier.send_email("Test Subject", "Test Body")
        
        mock_smtplib_smtp.assert_called_once_with("smtp.example.com", 587, timeout=10)
        mock_server_instance = mock_smtplib_smtp.return_value.__enter__.return_value

        mock_server_instance.login.assert_called_once_with("test@example.com", "test_email_password")
        mock_server_instance.sendmail.assert_called_once()
        
        from_addr, to_addrs, msg_str = mock_server_instance.sendmail.call_args[0]
        
        assert from_addr == "test@example.com"
        assert to_addrs == "user@example.com"
        
        sent_msg = message_from_string(msg_str, policy=policy.default)
        assert sent_msg.get_content().strip() == "Test Body"
        assert sent_msg['Subject'] == "Test Subject"


    def test_send_email_with_attachment(self, notifier, mock_smtplib_smtp, tmp_path):
        """
        NEW: Verifies that file attachments are correctly added to the email.
        This test assumes `send_email` is modified to accept an `attachments` list.
        """
        if not hasattr(notifier.send_email, "__defaults__") or "attachments" not in notifier.send_email.__code__.co_varnames:
            pytest.skip("Notifier.send_email does not support attachments yet.")
            
        log_file = tmp_path / "audit.log"
        log_file.write_text("This is a log file.")
        
        notifier.send_email("Test with Attachment", "See attached log.", attachments=[str(log_file)])
        
        mock_server_instance = mock_smtplib_smtp.return_value.__enter__.return_value
        _, _, msg_str = mock_server_instance.sendmail.call_args[0]
        sent_msg = message_from_string(msg_str, policy=policy.default)

        assert sent_msg.is_multipart()
        
        attachment_part = next(part for part in sent_msg.iter_attachments())
        assert attachment_part.get_filename() == "audit.log"
        assert attachment_part.get_content().decode().strip() == "This is a log file."

    def test_send_slack_webhook_success(self, notifier):
        """Verifies successful Slack message via webhook."""
        if not requests:
            pytest.skip("requests library not installed")
        with patch('requests.post', autospec=True) as mock_post:
            mock_post.return_value = MagicMock(status_code=200, text="ok")
            # Disable token to force webhook usage
            with patch.dict(os.environ, {"UPM_SLACK_TOKEN": ""}):
                notifier.send_slack("Hello Slack!")
            
            mock_post.assert_called_once()
            assert mock_post.call_args.kwargs['json']['text'] == "Hello Slack!"

# --- Integration Tests (Real Services or Local Servers) ---

class TestNotifierIntegration:

    @pytest.fixture
    def local_smtp_server(self):
        """
        NEW: Creates a real local SMTP server on a separate thread for testing.
        This allows testing the entire SMTP protocol without mocks.
        """
        class CustomSMTPServer(smtpd.SMTPServer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.received_messages = []
            
            def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
                self.received_messages.append(data)

        server = CustomSMTPServer(('127.0.0.1', 0), None)
        server_thread = threading.Thread(target=asyncore.loop, kwargs={'timeout': 1})
        server_thread.start()
        
        yield server.socket.getsockname()[0], server.socket.getsockname()[1], server.received_messages
        
        server.close()
        server_thread.join()

    def test_send_email_with_local_smtp_server(self, notifier, local_smtp_server):
        """
        MEDIUM PRIORITY: Tests sending an email to a real, local SMTP server,
        verifying the full communication protocol.
        """
        host, port, received_messages = local_smtp_server
        notifier.config["email"]["smtp_server"] = host
        notifier.config["email"]["smtp_port"] = port
        # FIX: Disable STARTTLS and AUTH for local, unencrypted server
        notifier.config["email"]["use_tls"] = False
        notifier.config["email"]["use_auth"] = False

        # This call now goes to the real local server
        notifier.send_email("Local SMTP Test", "Message Body")

        assert len(received_messages) == 1
        msg = message_from_bytes(received_messages[0], policy=policy.default)
        assert msg['Subject'] == "Local SMTP Test"
        assert msg.get_content().strip() == "Message Body"

    @pytest.mark.skipif(not os.environ.get("UPM_TEST_SLACK_WEBHOOK_URL"), reason="Requires real Slack webhook URL in environment")
    def test_send_real_slack_webhook_in_ci(self):
        """
        HIGH PRIORITY: A true integration test that sends a real message
        to a Slack webhook if the URL is provided in the CI environment.
        """
        if not requests:
            pytest.skip("requests library not installed")
            
        webhook_url = os.environ.get("UPM_TEST_SLACK_WEBHOOK_URL")
        config = {
            "notifications": {
                "slack": {"enabled": True, "webhook_url": webhook_url}
            }
        }
        notifier = Notifier(config)
        
        try:
            # This makes a real HTTP POST request to Slack
            with patch.dict(os.environ, {"UPM_SLACK_TOKEN": ""}):
                 notifier.send_slack("UPM CI/CD Test Message - Please Ignore")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Real Slack webhook notification failed: {e}")