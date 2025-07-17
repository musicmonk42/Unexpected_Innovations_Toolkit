# UPM Configuration & Policy Management

UPM’s behavior is controlled by configuration and policy files stored in your project’s root directory.

These enable secure customization of features, automation, and compliance.

---

## .unipkgrc – Main Configuration File

**Location:** `.unipkgrc` (YAML) in your project root.

**Purpose:** Controls general UPM settings, notifications, AWS/cloud integration, permissions, security, and audit logging.

**Sensitive Data:**  
Never store passwords, API keys, or secrets here—always use environment variables or a secure secrets manager.

---

### Key Fields and Structure

```yaml
offline: false                # Use only cached data (default: false)
verbose: false                # Enable detailed logs

notifications:
  email:
    enabled: false
    sender: "upm@yourdomain.com"
    recipient: "alert@yourdomain.com"
    smtp_server: "smtp.yourdomain.com"
    smtp_port: [587, 465]
    # password: Use UPM_EMAIL_PASSWORD env var!
  slack:
    enabled: false
    # webhook_url: Use UPM_SLACK_TOKEN env var!
    # token: Use UPM_SLACK_TOKEN env var!
    channel: "#alerts"
    template: "UPM Alert: {message}"
  min_severity_for_email: "ERROR"
  min_severity_for_slack: "WARNING"

aws:
  lambda:
    function_name: "your-ci-lambda-function"
    qualifier: "$LATEST"
  profile: "default"
  region: "us-east-1"
  # Credentials via AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars

permissions:
  allow_local_installs: true      # Allow local package installs
  lock_config_changes: false      # Prevent config modifications via UPM

security:
  encrypt_data: false             # Encrypt config, manifest, and lock files
  # encryption_key_path: ".unipkg.key"   # Use a secure secrets manager
  sign_manifests: false           # Sign manifests and lock files
  # private_key_path: ".private_key.pem" # Never store in VCS!
  public_key_path: ".public_key.pem"
  oauth:
    client_id: "your_client_id"
    # client_secret: Use UPM_OAUTH_SECRET env var!
  ssl_verify_policy_server: true
  # api_key: Use UPM_API_KEY env var!

  # --- Plugin Isolation and Sandboxing ---
  plugin_isolation: "subprocess"  # Options: "subprocess" (default), "docker" (future), "none" (NOT RECOMMENDED)
  plugin_timeout_seconds: 120     # Max seconds a plugin is allowed to run (default: 120)

logging:
  file_path: "unipkg_audit.log"
  console_style: "JSON"           # "JSON" or "HUMAN"
  async_logging: false
  remote_upload:
    enabled: false
    s3_bucket: "your-bucket"
    s3_prefix: "logs/"
    # kms_key_id: "your-kms-key-id"
Best Practices for Sensitive Data
Never hardcode: Do not commit secrets in .unipkgrc.

Always use env vars:

UPM_EMAIL_PASSWORD

UPM_SLACK_TOKEN

UPM_API_KEY

UPM_OAUTH_SECRET

AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION

Secrets manager: Integrate with AWS Secrets Manager, HashiCorp Vault, or similar in production.

Key management: Store all private keys, encryption keys, and sensitive files outside source control. Rotate keys regularly.

Example .unipkgrc
yaml
Copy
Edit
offline: false
verbose: true

notifications:
  email:
    enabled: true
    sender: "upm@example.com"
    recipient: "alert@example.com"
    smtp_server: "smtp.example.com"
    smtp_port: [587, 465]
  slack:
    enabled: true
    channel: "#alerts"
    template: "UPM Error: {message}"

security:
  encrypt_data: true
  encryption_key_path: ".unipkg.key"
  sign_manifests: true
  private_key_path: ".private_key.pem"
  public_key_path: ".public_key.pem"
  oauth:
    client_id: "your_client_id"
  plugin_isolation: "subprocess"
  plugin_timeout_seconds: 180

aws:
  lambda:
    function_name: "upm-ci"
    qualifier: "$LATEST"
  region: "us-east-1"

logging:
  async_logging: true
  remote_upload:
    enabled: true
    s3_bucket: "upm-logs"
    s3_prefix: "audit/"
    kms_key_id: "alias/upm-logs"
.unipkgpolicy.yaml – Policy File
Location: .unipkgpolicy.yaml in the project root.

Purpose: Enforces security, version pinning, allowed/blocked packages, and compliance.

Format: YAML.

Key Fields and Structure
yaml
Copy
Edit
blocked_packages:
  - "left-pad"
  - "old-vulnerable-lib"

allowed_packages:          # (Optional) If defined, only these are allowed
  - "requests"
  - "lodash"

pinned_versions:
  pip:
    requests: ">=2.28.1,<3.0.0"
    typer: "^0.9.0"
  npm:
    lodash: "4.17.21"
  cargo:
    serde: "==1.0.100"

require_api_key: true      # Require API key for UPM Web API

policy_server: "https://policy.example.com"  # (Optional) Remote policy server

permissions:               # Override .unipkgrc for CI/hardened mode
  allow_local_installs: false
  lock_config_changes: true
Best Practices for Policy Management
Policy always overrides config if in conflict.

Remote policy: If policy_server is defined, UPM merges remote and local policies, prioritizing remote.

Version pinning: Use semantic constraints (e.g., >=, ^) for precise control.

Blocked/allowed lists: Strictly enforce to prevent supply chain risk.

Example .unipkgpolicy.yaml
yaml
Copy
Edit
blocked_packages:
  - "insecure-lib"

allowed_packages:
  - "requests"
  - "express"

pinned_versions:
  pip:
    requests: ">=2.32.4"
  npm:
    express: "^4.20.0"

require_api_key: true

permissions:
  allow_local_installs: false
🔐 Security, Compliance, and Operations
Signing
Enable security.sign_manifests with private_key_path and public_key_path to cryptographically sign .unipkgrc, .unipkgpolicy.yaml, and all lockfiles:

sh
Copy
Edit
unipkg sign-config .unipkgrc --private-key .private_key.pem
Encryption
Enable security.encrypt_data for encrypted configs and manifests (key at encryption_key_path).

Secrets Rotation
Rotate keys with a secrets manager and document all rotation in your operational policies.

Policy Validation
Use unipkg validate-policy (coming soon) to check policy files before deployment.

Audit Logging
Enable logging.async_logging and logging.remote_upload for tamper-evident, offsite log retention.

🛡️ Plugin Isolation & Sandboxing (NEW)
UPM always runs all plugins in isolated subprocesses by default (plugin_isolation: "subprocess").
This prevents plugins from directly crashing or modifying the main UPM process.

On Linux: Subprocesses provide strong isolation.

On Windows/macOS: Isolation is limited to process boundaries and OS controls.

(Future) For stricter isolation, you may use "plugin_isolation: docker" (if/when supported).

Plugin Timeout:
Set plugin_timeout_seconds in the security section to restrict how long any plugin may run.

All plugins must include the required sandbox entrypoint block—see PLUGINS.md and SECURITY.md.

🛡️ Operational Security & Supply Chain Hardening
Never commit secrets to VCS—always .gitignore all key, credential, and lock files.

Always run UPM and plugins in a container, VM, or hardened environment for CI/CD.

Monitor and rotate all secrets, keys, and credentials as part of incident response.

Keep all UPM, plugin, and dependency versions up to date.

For further details, see:
USAGE.md for common workflows

API.md for programmatic access

SECURITY.md for threat model and hardening

docs/ for advanced topics

End of CONFIGURATION.md