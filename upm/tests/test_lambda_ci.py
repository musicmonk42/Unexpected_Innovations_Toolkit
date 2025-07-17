# upm/tests/test_lambda_ci.py
import pytest
import os
import logging
import json
import zipfile
from io import BytesIO
from unittest.mock import patch, MagicMock
from datetime import datetime
import asyncio
import time

import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

try:
    from moto import mock_aws
    _MOTO_AVAILABLE = True
except ImportError:
    _MOTO_AVAILABLE = False
    print("Warning: 'moto' not installed. Skipping tests that require AWS mocking.")

from upm.lambda_ci import LambdaCI, LambdaCIInvocationError
from upm.logging_utils import flush_logs, AUDIT_LOGGER, configure_logging, shutdown_logging

# --- Fixtures ---

@pytest.fixture
def aws_credentials():
    """Mocked AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

@pytest.fixture
def mock_aws_lambda(aws_credentials):
    """
    Creates a mock AWS environment using moto with a dummy Lambda function.
    """
    if not _MOTO_AVAILABLE:
        pytest.skip("Moto library not available for AWS mocking tests.")

    lambda_code = """
import json
def handler(event, context):
    return {'statusCode': 200, 'body': json.dumps({'status': 'success from moto'})}
"""
    zip_output = BytesIO()
    with zipfile.ZipFile(zip_output, 'w') as zf:
        zf.writestr('lambda_function.py', lambda_code)
    zip_output.seek(0)
    
    with mock_aws():
        conn = boto3.client("iam")
        role_arn = conn.create_role(
            RoleName="test-lambda-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            })
        )["Role"]["Arn"]

        lambda_client = boto3.client("lambda")
        lambda_client.create_function(
            FunctionName="test-lambda", Runtime="python3.9", Role=role_arn,
            Handler="lambda_function.handler", Code={"ZipFile": zip_output.read()}
        )
        yield lambda_client

@pytest.fixture
def mock_manifest_file(tmp_path):
    manifest_dir = tmp_path / "project"
    manifest_dir.mkdir(exist_ok=True)  # Allow directory to exist
    manifest_file = manifest_dir / "unipkg.yaml"
    manifest_file.write_text("dependencies: {}")
    
    with patch('os.path.getmtime', return_value=datetime.now().timestamp()):
        yield manifest_file

@pytest.fixture
def temp_project_root(tmp_path):
    """Provides a temporary project root directory."""
    project_dir = tmp_path / "project"
    project_dir.mkdir(exist_ok=True)
    return project_dir

@pytest.fixture(autouse=True)
def caplog_audit(caplog, temp_project_root):
    """Configure logging with JSON format for tests."""
    log_file = temp_project_root / "test_audit.log"
    configure_logging(log_file_path=str(log_file), log_format="json", disable_concurrent_log_handler=True, verbose=True)
    with caplog.at_level(logging.DEBUG, logger='unipkg_audit'):
        yield caplog
    flush_logs()
    shutdown_logging()

# --- Utility to wait for logs ---
async def wait_for_log(caplog, text_to_find, timeout=2.0):
    start_time = time.time()
    while time.time() - start_time < timeout:
        if text_to_find in caplog.text:
            return True
        await asyncio.sleep(0.01)
    return False

# --- Unit Tests with Direct Mocks ---

class TestLambdaCIUnit:
    @pytest.fixture
    def lambda_ci_instance(self):
        config = {"aws": {"lambda": {"function_name": "test-lambda"}}}
        with patch('upm.lambda_ci.boto3.client') as mock_boto_client:
            mock_lambda_client = MagicMock()
            mock_boto_client.return_value = mock_lambda_client
            instance = LambdaCI(config)
            instance.lambda_client = mock_lambda_client
            yield instance

    @pytest.mark.asyncio
    async def test_invoke_ci_lambda_function_error(self, lambda_ci_instance, mock_manifest_file, temp_project_root):
        """Tests handling of an error returned from the Lambda function itself."""
        lambda_ci_instance.lambda_client.invoke.return_value = {
            "StatusCode": 200,
            "FunctionError": "Unhandled",
            "Payload": BytesIO(json.dumps({"errorMessage": "Task timed out"}).encode('utf-8'))
        }
        result = lambda_ci_instance.invoke_ci(str(mock_manifest_file.parent))
        assert result is False
        
        flush_logs()
        log_file = temp_project_root / "test_audit.log"
        for _ in range(10):
            if log_file.exists() and log_file.read_text().strip():
                break
            time.sleep(0.5)
        assert log_file.exists(), f"Log file not found at {log_file}"
        log_content = log_file.read_text()

        assert "Lambda function execution failed" in log_content
        assert "Task timed out" in log_content

    @pytest.mark.asyncio
    async def test_init_warns_on_keys_in_config(self, temp_project_root):
        """Verifies a CRITICAL warning is logged if AWS keys are in the config file."""
        config_with_keys = {
            "aws": {
                "access_key": "DUMMY_KEY_IN_CONFIG",
                "secret_key": "DUMMY_SECRET_IN_CONFIG",
                "lambda": {"function_name": "test-lambda"}
            }
        }
        with patch('upm.lambda_ci.boto3.client'):
            LambdaCI(config_with_keys)
            time.sleep(0.5)  # Allow time for log to be written

        flush_logs()
        log_file = temp_project_root / "test_audit.log"
        for _ in range(10):
            if log_file.exists() and log_file.read_text().strip():
                break
            time.sleep(0.5)
        assert log_file.exists(), f"Log file not found at {log_file}"
        
        log_content = log_file.read_text()
        assert "CRITICAL" in log_content and "AWS access/secret key found in config" in log_content, \
            f"CRITICAL log entry for AWS keys not found in log: {log_content}"

    def test_init_configures_boto_with_timeouts(self):
        """Verifies that boto3.client is called with timeout configurations."""
        config = {"aws": {"lambda": {"function_name": "test-lambda"}}}
        with patch('upm.lambda_ci.boto3.client') as mock_boto_client:
            LambdaCI(config)
            mock_boto_client.assert_called_once()
            call_args, call_kwargs = mock_boto_client.call_args 
            
            assert call_args[0] == 'lambda' 
            
            assert 'config' in call_kwargs
            boto_config = call_kwargs['config']
            assert isinstance(boto_config, Config)
            assert boto_config.connect_timeout == 60 
            assert boto_config.read_timeout == 60