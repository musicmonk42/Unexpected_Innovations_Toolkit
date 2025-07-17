# upm/lambda_ci.py
import boto3
import json
import os
import logging
from botocore.exceptions import ClientError
from botocore.config import Config
from upm.logging_utils import AUDIT_LOGGER, AuditOperation, log_audit # Import log_audit

class LambdaCIInvocationError(Exception):
    """Custom exception for Lambda CI invocation failures."""
    pass

class LambdaCI:
    def __init__(self, config: dict):
        self.config = config
        self.lambda_function_name = config.get("aws", {}).get("lambda", {}).get("function_name")
        if not self.lambda_function_name:
            raise ValueError("Lambda function name not configured in 'aws.lambda.function_name'.")

        # CRITICAL check for AWS keys in config
        if config.get("aws", {}).get("access_key") or config.get("aws", {}).get("secret_key"):
            log_audit(logging.CRITICAL, # Use log_audit here
                "AWS access/secret key found in config! "
                "These should ideally be managed via IAM roles or environment variables, not hardcoded.",
                operation=AuditOperation.SECURITY_EVENT
            )

        try:
            # FIX: Initialize boto3 client with a configuration object for timeouts.
            boto_config = Config(
                connect_timeout=60,
                read_timeout=60
            )
            self.lambda_client = boto3.client('lambda', config=boto_config)
        except Exception as e:
            log_audit(logging.ERROR, # Use log_audit here
                f"Failed to initialize AWS Lambda client: {e}",
                operation=AuditOperation.CLI_INVOKE,
                context={"error": str(e)}
            )
            raise

    def invoke_ci(self, project_path: str) -> bool:
        """
        Invokes the configured AWS Lambda CI function.

        Args:
            project_path (str): The path to the project directory containing the manifest.

        Returns:
            bool: True if the Lambda was invoked successfully and returned a success status,
                  False otherwise.
        """
        try:
            # For now, we'll just send the project path.
            # In a real scenario, you might upload the project as a zip to S3
            # and pass the S3 key to the Lambda.
            payload = {
                "project_path": project_path,
                "timestamp": json.dumps(os.path.getmtime(os.path.join(project_path, "unipkg.yaml")))
            }

            response = self.lambda_client.invoke(
                FunctionName=self.lambda_function_name,
                InvocationType='RequestResponse',  # Synchronous invocation
                Payload=json.dumps(payload)
            )

            # Read the payload from the response
            response_payload = json.loads(response['Payload'].read().decode('utf-8'))

            if response.get('FunctionError'):
                log_audit(logging.ERROR, # Use log_audit here
                    f"Lambda function execution failed: {response.get('FunctionError')}. "
                    f"Payload: {response_payload}",
                    operation=AuditOperation.SECURITY_EVENT,
                    context={"lambda_error": response.get('FunctionError'), "response_payload": response_payload}
                )
                return False

            if response['StatusCode'] == 200 and response_payload.get('status') == 'success':
                log_audit(logging.INFO, # Use log_audit here
                    "Lambda CI invoked successfully.",
                    operation=AuditOperation.CLI_INVOKE,
                    context={"response": response_payload}
                )
                return True
            else:
                log_audit(logging.WARNING, # Use log_audit here
                    f"Lambda CI invocation returned non-success status. "
                    f"Status Code: {response['StatusCode']}, Payload: {response_payload}",
                    operation=AuditOperation.CLI_INVOKE,
                    context={"status_code": response['StatusCode'], "response_payload": response_payload}
                )
                return False

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            error_message = e.response.get("Error", {}).get("Message")
            log_audit(logging.ERROR, # Use log_audit here
                f"AWS Lambda Client Error: {error_code} - {error_message}",
                operation=AuditOperation.CLI_INVOKE,
                context={"error_code": error_code, "error_message": error_message}
            )
            return False
        except Exception as e:
            log_audit(logging.ERROR, # Use log_audit here
                f"An unexpected error occurred during Lambda CI invocation: {e}",
                operation=AuditOperation.CLI_INVOKE,
                context={"error": str(e)}
            )
            raise LambdaCIInvocationError(f"Failed to invoke Lambda CI: {e}")