# tests/test_logging_utils.py

import pytest
import os
import logging
import gzip
import threading
import json
from unittest.mock import patch, MagicMock
import asyncio # Required for async operations in some tests

# --- New imports for advanced testing ---
import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet # FIX: Import Fernet for use in tests

# Conditional import for moto
try:
    from moto import mock_aws
    _MOTO_AVAILABLE = True
except ImportError:
    _MOTO_AVAILABLE = False
    # print("Warning: 'moto' not installed. Skipping tests that require AWS mocking.") # Don't print in tests directly

# --- Assumed imports from the application's logging utility ---
# These classes are assumed to exist based on the test analysis.
from upm.logging_utils import (
    configure_logging, # Corrected from setup_logging
    # SensitiveDataFilter, # Not directly imported or tested in provided code
    # RotatingEncryptedFileHandler, # Not directly imported or tested in provided code
    # S3LogUploader, # Not directly imported or tested in provided code
    AUDIT_LOGGER,
    shutdown_logging,
    decrypt_audit_log_file # Assumed helper for reading encrypted logs
)

# --- Fixtures ---

@pytest.fixture
def temp_log_dir(tmp_path):
    """Provides a temporary directory for log files."""
    return tmp_path

@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

@pytest.fixture(scope="function")
def mock_s3_bucket(aws_credentials):
    """Creates a mock S3 bucket using moto for realistic boto3 simulation."""
    if not _MOTO_AVAILABLE:
        pytest.skip("Moto library not available for AWS mocking tests.")
    with mock_aws():
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="test-log-bucket")
        yield s3

# --- Core Functionality Tests ---

class TestBasicLoggingAndRedaction:
    # `setup_logging` is now `configure_logging`.
    # Redaction is handled by `redact_secrets` which is used by `JSONFormatter` and `HumanReadableFormatter`.
    # The logging configuration is typically done once via conftest.
    # To test redaction explicitly, we need to create a new logger and handler for this specific test
    # to ensure it's independent of the global AUDIT_LOGGER setup by conftest.
    
    def test_redaction_works(self, temp_log_dir, caplog):
        """Verifies that the redact_secrets function and formatter correctly redact patterns."""
        log_file = temp_log_dir / "app.log"
        
        # We need to create a new logger and handler for this specific test
        # to ensure it's independent of the global AUDIT_LOGGER setup by conftest.
        logger_name = "test_redact_logger"
        test_logger = logging.getLogger(logger_name)
        test_logger.handlers.clear() # Clear existing handlers from previous tests
        test_logger.setLevel(logging.INFO)
        
        file_handler = logging.FileHandler(log_file)
        # Use JSONFormatter for redaction capabilities defined in logging_utils.py
        # You need to import JSONFormatter from logging_utils.py
        from upm.logging_utils import JSONFormatter
        file_handler.setFormatter(JSONFormatter())
        test_logger.addHandler(file_handler)
        
        test_logger.info("User logged in with password=secret12345 api_key=topsecret")
        
        # Ensure log is flushed and closed
        for handler in test_logger.handlers:
            handler.flush()
            handler.close()
        test_logger.handlers.clear() # Remove handlers

        with open(log_file, "r") as f:
            content_json = f.read()
            log_entry = json.loads(content_json) # It should be JSON
            assert "password=secret12345" not in log_entry["message"]
            assert "api_key=topsecret" not in log_entry["message"]
            assert "password=[REDACTED]" in log_entry["message"]
            assert "api_key=[REDACTED]" in log_entry["message"]


    def test_json_format_with_large_payload(self, temp_log_dir):
        """Tests JSON formatting with a large log message to check for truncation."""
        log_file = temp_log_dir / "app.json.log"
        large_string = "A" * 10_000
        
        logger_name = "test_json_logger"
        test_logger = logging.getLogger(logger_name)
        test_logger.handlers.clear()
        test_logger.setLevel(logging.INFO)
        
        file_handler = logging.FileHandler(log_file)
        from upm.logging_utils import JSONFormatter
        file_handler.setFormatter(JSONFormatter())
        test_logger.addHandler(file_handler)
        
        test_logger.info("Large payload event", extra={"payload_data": large_string}) # Use 'payload_data' to avoid conflict with 'payload' key if any.
        
        # Ensure log is flushed and closed
        for handler in test_logger.handlers:
            handler.flush()
            handler.close()
        test_logger.handlers.clear()

        with open(log_file, "r") as f:
            log_entry_str = f.read()
            log_entry = json.loads(log_entry_str)
            assert log_entry["message"] == "Large payload event"
            assert "payload_data" in log_entry # Check if extra field exists
            assert log_entry["payload_data"] == large_string
            assert len(log_entry["payload_data"]) == 10_000

# --- High-Priority Concurrency Test ---

class TestConcurrency:
    def test_concurrent_logging_from_threads(self, temp_log_dir):
        """
        Stress-tests logging from multiple threads to ensure no interleaved lines or corruption.
        """
        log_file = temp_log_dir / "concurrent.log"
        num_threads = 10
        logs_per_thread = 100
        
        logger_name = "test_concurrent_logger"
        test_logger = logging.getLogger(logger_name)
        test_logger.handlers.clear()
        test_logger.setLevel(logging.INFO)
        
        # Use SecureRotatingFileHandler (which uses a QueueHandler)
        # Assuming SecureRotatingFileHandler is part of logging_utils.
        from upm.logging_utils import SecureRotatingFileHandler, HumanReadableFormatter # Assuming HumanReadableFormatter
        file_handler = SecureRotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=1)
        file_handler.setFormatter(HumanReadableFormatter())
        
        # For actual concurrent writing through threads, the logging system
        # should ideally use a QueueHandler (which SecureRotatingFileHandler already might if configured).
        # We need to manually add handlers if we are not using the main AUDIT_LOGGER.
        test_logger.addHandler(file_handler)

        def log_worker(thread_id):
            # Get the logger by name in each thread.
            # Logging module is thread-safe for emitting records.
            logger = logging.getLogger(logger_name)
            for i in range(logs_per_thread):
                logger.info(f"Log entry {i} from thread {thread_id}")

        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=log_worker, args=(i,), name=f"Worker-{i}")
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        
        # Proper shutdown of logging to ensure all queued logs are processed
        # For a specific logger, iterate its handlers and flush/close.
        for handler in test_logger.handlers:
            handler.flush()
            handler.close()
        test_logger.handlers.clear()

        with open(log_file, "r") as f:
            lines = f.readlines()
            # Check for total number of lines
            assert len(lines) == num_threads * logs_per_thread
            # Check for corruption by ensuring each line is complete
            for line in lines:
                assert line.endswith("\n")
                assert "Worker-" in line


# --- S3 Upload and Rotation Tests ---

@pytest.mark.skipif(not _MOTO_AVAILABLE, reason="Skipping moto tests as library is not available.")
class TestS3Uploads:
    
    # We need to mock the `_upload_logs_on_shutdown` function which is called globally
    # by `shutdown_logging()`.
    @patch('upm.logging_utils._upload_logs_on_shutdown', new_callable=MagicMock)
    def test_s3_upload_failure_and_retry(self, mock_upload_logs_on_shutdown, temp_log_dir, aws_credentials, caplog):
        """
        Simulates S3 upload failures and verifies that the retry logic works
        when `_upload_logs_on_shutdown` is called.
        """
        # Configure `_upload_logs_on_shutdown` to simulate failures then success.
        # This function is not directly retried by tenacity within logging_utils.
        # Tenacity retries are for NetworkUtil's http requests.
        # `_upload_logs_on_shutdown` calls `boto3.client('s3').upload_file`,
        # which can be patched.
        
        # We need to make sure the global AUDIT_LOGGER uses this setup.
        log_file = temp_log_dir / "rotating.log"
        # Reconfigure AUDIT_LOGGER globally for this test, making sure it points to temp_log_dir
        # and has S3 upload configured.
        
        # Patch boto3.client('s3').upload_file to simulate errors
        with patch('boto3.client') as mock_boto_client:
            mock_s3_client = MagicMock()
            mock_boto_client.return_value = mock_s3_client
            
            # Simulate transient S3 errors for upload_file
            mock_s3_client.upload_file.side_effect = [
                ClientError({'Error': {'Code': '500', 'Message': 'Internal Error'}}, 'upload_file'),
                ClientError({'Error': {'Code': '503', 'Message': 'Service Unavailable'}}, 'upload_file'),
                None # Success on third attempt
            ]

            configure_logging(
                log_file_path=str(log_file),
                verbose=True,
                remote_upload_config={ # This configures the global _remote_upload_config_global
                    "enabled": True,
                    "s3_bucket": "test-log-bucket",
                    "s3_prefix": "test_logs/",
                    "retries": 3 # This retry count is used by `_upload_logs_on_shutdown`
                }
            )
            
            # Write some log data to trigger potential rotation/upload on shutdown
            AUDIT_LOGGER.info("This log message will be uploaded.")
            
            # Shut down logging, which will trigger the upload
            with caplog.at_level(logging.ERROR, logger="unipkg_audit"):
                shutdown_logging()
            
            # Assert that upload_file was called multiple times
            assert mock_s3_client.upload_file.call_count == 3
            # Check for errors logged during retries by the `_upload_logs_on_shutdown` function
            assert "Failed to upload audit log to S3" in caplog.text
            
            # Clean up handlers after test to avoid interference
            for handler in AUDIT_LOGGER.handlers[:]:
                AUDIT_LOGGER.removeHandler(handler)
                handler.close()

    def test_s3_upload_on_rotation_with_moto(self, temp_log_dir, mock_s3_bucket, caplog):
        """
        Tests log rotation with a real S3 upload simulated by moto.
        """
        log_file = temp_log_dir / "s3_rotating.log"
        
        configure_logging(
            log_file_path=str(log_file),
            verbose=False, # Set to False to avoid excessive console output
            log_max_bytes=1000, # Small size to force rotation
            log_backup_count=1,
            remote_upload_config={
                "enabled": True,
                "s3_bucket": "test-log-bucket",
                "s3_prefix": "s3_rotation_logs/",
                # Default retries are fine for moto
            }
        )
        
        # Write enough data to trigger a rotation
        AUDIT_LOGGER.info("This is log line one, just before rotation boundary.")
        AUDIT_LOGGER.info("This is log line two, which should trigger rotation.")
        
        # Shut down logging to ensure rotation and upload occurs
        with caplog.at_level(logging.INFO, logger="unipkg_audit"):
            shutdown_logging()
        
        # The rotated file should be in the S3 bucket.
        # Check objects in the mock S3 bucket.
        response = mock_s3_bucket.list_objects_v2(Bucket="test-log-bucket")
        
        assert "Contents" in response
        uploaded_files = [obj['Key'] for obj in response['Contents']]
        
        # The naming convention for rotated files is `basename.log.1`, then compressed to `.gz`
        # and prefixed by `s3_prefix`.
        # e.g., s3_rotation_logs/s3_rotating.log.1_1678888888.log (timestamped)
        assert any("s3_rotating.log.1" in key for key in uploaded_files) # Look for the rotated file
        
        # Also check logs for confirmation messages
        assert "Uploaded log file" in caplog.text or "audit log to S3" in caplog.text
        
        # Clean up handlers after test to avoid interference
        for handler in AUDIT_LOGGER.handlers[:]:
            AUDIT_LOGGER.removeHandler(handler)
            handler.close()


# --- Fuzzing and Robustness Tests ---

class TestFuzzing:

    @pytest.mark.parametrize("data_type", ["binary", "text_ascii", "text_unicode"])
    def test_decryption_fuzzing(self, data_type, temp_log_dir):
        """
        Fuzzes the decryption function with varied inputs to ensure it never crashes.
        """
        fuzzed_file = temp_log_dir / "fuzzed.log.enc"
        
        # Encryption key for Fernet (must be URL-safe base64 encoded, 32 bytes raw)
        key = Fernet.generate_key()
        
        if data_type == "binary":
            fuzzed_content = os.urandom(100) # Raw random bytes
        elif data_type == "text_ascii":
            fuzzed_content = b"random ascii text that is not a valid encrypted token"
        elif data_type == "text_unicode":
            fuzzed_content = "乱れた文字".encode('utf-8') # Malformed unicode bytes

        # Write the fuzzed content directly to the file
        with open(fuzzed_file, 'wb') as f:
            f.write(fuzzed_content)
            
        try:
            # The decrypt_audit_log_file function should handle garbage data without crashing.
            # It should return a string indicating error or raise a DecryptionError if it tries to parse JSON.
            # As per logging_utils.py, it returns an error string.
            decrypted_output = decrypt_audit_log_file(str(fuzzed_file), key)
            assert "Failed to decrypt log entry" in decrypted_output or \
                   "An unexpected error occurred" in decrypted_output # Check for expected error messages
        except Exception as e:
            # We expect a controlled failure, not an unexpected crash.
            # If `decrypt_audit_log_file` raises something else, that's a test failure.
            pytest.fail(f"An unexpected exception was raised by decryption fuzzing: {type(e).__name__}: {e}")