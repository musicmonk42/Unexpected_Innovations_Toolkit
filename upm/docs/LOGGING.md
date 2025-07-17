# UPM Logging: Audit, Debugging, and Security

UPM’s logging system provides structured, secure, and auditable records of all operations.

Logs are essential for debugging, compliance, security monitoring, and forensics in modern dependency workflows.

---

## 📊 Audit Log File

**Location:**  
`unipkg_audit.log` in the working directory (configurable via `logging.file_path` in `.unipkgrc` or `UPM_AUDIT_LOG` env var).

**Format:**  
Structured JSON (default, for compatibility with ELK Stack, Splunk, jq, etc.).

**Log Entry Fields:**

- `timestamp`: UTC (e.g., "2025-07-12T06:03:00Z")
- `level`: DEBUG, INFO, WARNING, ERROR, CRITICAL
- `user`: Initiator (from `get_current_user()`)
- `operation`: Action performed (e.g., install, doctor, log_decrypt)
- `context`: Operation details (e.g., `{"ecosystem": "pip", "package": "requests"}`)
- `message`: Human-readable summary
- `exception`: Optional traceback (errors only)
- `sandboxed`: Boolean, true if the operation (plugin) ran in a sandboxed subprocess (added for plugin actions)
- `plugin_name`: (If applicable) Name of the plugin involved

**Example Log Entry:**

```json
{
  "timestamp": "2025-07-12T06:03:00Z",
  "level": "INFO",
  "user": "jdoe",
  "operation": "install",
  "context": {"ecosystem": "pip", "package": "requests", "version": "2.32.4"},
  "message": "Successfully installed requests from pip",
  "sandboxed": true,
  "plugin_name": "pip"
}
🔒 Security Features
Sensitive Data Redaction:
All API keys, tokens, passwords, OAuth secrets, and credentials are automatically redacted before writing to disk (see logging_utils.py for patterns).

Encryption:
Set security.encrypt_data: true in .unipkgrc to AES-encrypt logs with a Fernet key (path at security.encryption_key_path).

Secure File Permissions:
Log file permissions set to 0600 (owner read/write only) on Unix-like systems.

Log Rotation:
Logs auto-rotate at 10MB (default), with 5 backups. Configurable via logging.max_size_mb and logging.backup_count.

Remote Upload:
Logs can be uploaded to S3 on shutdown, encrypted with AWS KMS, if logging.remote_upload.enabled: true.

🚨 Plugin Execution & Sandboxing in Logs
All plugin actions (install, uninstall, list, doctor, etc.) are logged with sandboxed: true and include the plugin_name.

Plugin errors or timeouts are always logged at ERROR or CRITICAL with full exception/traceback info, and a note if the error was raised by a sandboxed subprocess.

Sandbox escape attempts (policy violation, forbidden syscall, unexpected output) are logged at CRITICAL with details.

Process timeouts (e.g., plugins killed after plugin_timeout_seconds) are also logged.

Example Plugin Error Log Entry:

json
Copy
Edit
{
  "timestamp": "2025-07-12T06:15:13Z",
  "level": "ERROR",
  "user": "jdoe",
  "operation": "install",
  "context": {"ecosystem": "pip", "package": "evilplugin"},
  "message": "Plugin 'pip' failed in sandboxed process: TimeoutExpired after 120s",
  "exception": "Traceback (most recent call last): ...",
  "sandboxed": true,
  "plugin_name": "pip"
}
🚨 Log Levels and Verbosity
Levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

Default: INFO (change via UPM_AUDIT_LOG_LEVEL or .unipkgrc)

Verbose Mode: Use --verbose or -v CLI flag to set level to DEBUG and enable detailed console output.

🖥️ Console Output
Default: Errors, warnings, and success messages printed to terminal.

Verbose Mode: All debug/trace messages shown with --verbose.

Style:

JSON: (default) for easy parsing/log ingestion

HUMAN: Plain text (set via UPM_AUDIT_CONSOLE_STYLE=HUMAN or .unipkgrc)

Color:
Uses typer or colorama for colored messages (red = error, yellow = warning).

⚡ Asynchronous Logging
Non-Blocking:
Enable with logging.async_logging: true or UPM_AUDIT_ASYNC_LOGGING=1.
Logs are queued in-memory and written by a background thread for performance.

Warning:
If the process is killed abruptly (e.g., kill -9), queued logs may be lost.
Use upm.logging_utils.shutdown_logging() for graceful shutdown.

Configuration:

yaml
Copy
Edit
logging:
  async_logging: true
🌐 Remote Log Upload
S3 Upload:
Enable via logging.remote_upload.enabled: true to upload logs to S3 with KMS encryption at shutdown.

Sample Configuration:

yaml
Copy
Edit
logging:
  remote_upload:
    enabled: true
    s3_bucket: "upm-logs"
    s3_prefix: "audit/"
    kms_key_id: "alias/upm-logs"
🔑 Log Decryption Tool
Command:

sh
Copy
Edit
unipkg log-decrypt <path_to_audit_log_file>
Requirements:

cryptography package (pip install cryptography)

Access to the Fernet key (security.encryption_key_path)

Output:
Decrypted JSON log entries to the console.

Example:

sh
Copy
Edit
unipkg log-decrypt unipkg_audit.log
Decrypted Output:

json
Copy
Edit
{
  "timestamp": "2025-07-12T06:03:00Z",
  "level": "INFO",
  "user": "jdoe",
  "operation": "install",
  "context": {"ecosystem": "pip", "package": "requests"},
  "message": "Successfully installed requests"
}
🛠️ Best Practices
Secure Storage:
Store unipkg_audit.log and your encryption keys in a secure, non-public location, excluded from version control.

Enable Encryption:
Always set security.encrypt_data: true for production and sensitive environments.

Use Async Logging:
Recommended for high-throughput or CI/CD scenarios.

Remote Upload:
Use S3 with KMS encryption for compliance/auditability.

Log Analysis:
Parse JSON logs using tools like jq, ELK Stack, or Splunk for real-time monitoring and alerting.

Plugin Errors:
Regularly review logs for plugin sandbox violations, timeouts, and CRITICAL errors—these may indicate malicious or misbehaving plugins.

Audit for Process Isolation:
All plugin actions should log sandboxed: true—if not, update your UPM version and review SECURITY.md.

📚 Configuration Reference
Minimal Logging Section:

yaml
Copy
Edit
logging:
  file_path: "unipkg_audit.log"
  console_style: "JSON"
  async_logging: true
  max_size_mb: 10
  backup_count: 5
  remote_upload:
    enabled: true
    s3_bucket: "upm-logs"
    s3_prefix: "audit/"
    kms_key_id: "alias/upm-logs"

security:
  encrypt_data: true
  encryption_key_path: ".unipkg.key"
See CONFIGURATION.md for all details.

🔗 For More Information
USAGE.md — Main usage and workflow guide

API.md — Programmatic logging and API usage

SECURITY.md — Threat model, tamper-evidence, compliance

PLUGINS.md — Plugin authoring, sandboxing, and isolation requirements

End of LOGGING.md