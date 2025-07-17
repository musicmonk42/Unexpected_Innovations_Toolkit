# UPM USAGE GUIDE

_Last updated: 2025-07-16_

---

## Table of Contents
- [What is UPM?](#what-is-upm)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Plugin Ecosystem](#plugin-ecosystem)
- [Configuration](#configuration)
- [Typical Workflows](#typical-workflows)
- [Security Model & Best Practices](#security-model--best-practices)
- [SBOM Generation & Verification](#sbom-generation--verification)
- [Audit Logs](#audit-logs)
- [Troubleshooting](#troubleshooting)
- [Support & Contribution](#support--contribution)

---

> ⚠️ **SECURITY WARNING**  
> **UPM plugins are always run in an isolated subprocess by default** (process isolation).  
> This provides strong safety, but is NOT a full OS or container sandbox.  
> Only use official or trusted plugins.  
> Every plugin **must** include the sandbox entrypoint (see [PLUGINS.md](PLUGINS.md)).  
> Review all configuration/security warnings before production.

---

## What is UPM?

**UPM (Universal Package Manager)** is a cross-ecosystem package manager—supporting Python (pip), Node.js (npm), Rust (cargo), and more via plugins.  
Built for **reproducibility, security, and supply chain transparency**, UPM supports automated SBOM and audit log generation for every project.

---

## Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/yourorg/upm.git
    cd upm
    ```

2. **Install Python dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

3. **(Optional) For plugin support:**
    - Rust: https://rustup.rs/
    - Node.js: https://nodejs.org/

4. **Install cyclonedx-py (for SBOM support):**
    ```sh
    pip install cyclonedx-py
    ```

---

## Quick Start

```sh
# Initialize a new project
unipkg init

# Add a package (Python/Node/Rust)
unipkg install pip requests
unipkg install npm lodash
unipkg install cargo serde

# List installed packages
unipkg list pip
unipkg list npm
unipkg list cargo

# Upgrade a package
unipkg upgrade pip requests

# Remove a package
unipkg uninstall npm lodash
Plugin Ecosystem
UPM supports plugins for each language/ecosystem.

Installed plugins are listed in your project manifest.

Plugins can be enabled/disabled/extended for custom or internal use.

sh
Copy
Edit
# List available plugins
unipkg plugins list

# Enable or disable plugins
unipkg plugins enable <name>
unipkg plugins disable <name>
Security Note:
Only enable plugins from trusted, signed sources.
All plugins are always run in isolated subprocesses (see PLUGINS.md), but never treat plugins as fully sandboxed.
See Security Model & Best Practices.

Configuration
UPM reads settings from .unipkgrc in your project root.

Never store secrets in this file!
Use environment variables for sensitive values.

Example .unipkgrc:

yaml
Copy
Edit
offline: false
verbose: false
notifications:
  email:
    enabled: true
    sender: "alerts@yourcompany.com"
    recipient: "devops@yourcompany.com"
    smtp_server: "smtp.yourcompany.com"
    # password: Use UPM_EMAIL_PASSWORD environment variable!
Override a config for one command:

sh
Copy
Edit
UPM_EMAIL_PASSWORD=yourpassword unipkg install pip requests
Typical Workflows
Reproducible Environment Setup
sh
Copy
Edit
unipkg init
unipkg install pip -r requirements.txt
unipkg install npm
unipkg build cargo
Upgrading All Packages
sh
Copy
Edit
unipkg upgrade pip --all
unipkg upgrade npm --all
unipkg upgrade cargo --all
Project Health Check
sh
Copy
Edit
unipkg doctor
Runs ecosystem checks (pip check, npm audit, cargo audit, etc).

Security Model & Best Practices
Plugins:

All plugins are always run in isolated subprocesses for process isolation.

This blocks plugins from crashing the main process but is not a full OS sandbox—plugins still run with your user privileges.

Every plugin must include the required sandbox entrypoint.

See PLUGINS.md for the entrypoint code and full requirements.

Use only official or reviewed plugins.

Always run UPM in a container/VM for untrusted plugins or multi-tenant CI/CD.

Never store credentials/API keys in config files.

Enable manifest and lockfile signing for supply chain protection.

Regularly rotate and verify audit logs and SBOMs.

Example config for signed manifests:

yaml
Copy
Edit
security:
  sign_manifests: true
  public_key_path: ".public_key.pem"
  # private_key_path: Use env var!
SBOM Generation & Verification
UPM can generate a Software Bill of Materials (SBOM) in CycloneDX format.

To generate and sign an SBOM:

sh
Copy
Edit
bash scripts/generate_sbom.sh --sign YOUR_GPG_KEY_ID
# Creates sbom.json, sbom.json.sha256, sbom.json.asc
To verify an SBOM:

sh
Copy
Edit
sha256sum -c sbom.json.sha256   # Linux
shasum -a 256 -c sbom.json.sha256  # macOS

gpg --recv-keys YOUR_GPG_KEY_ID
gpg --verify sbom.json.asc sbom.json
Audit Logs
All package, plugin, and security actions are logged to unipkg_audit.log.

Logs are structured, tamper-evident, and rotated regularly.

All plugin actions include a sandboxed: true flag for process isolation.

Example logging config:

yaml
Copy
Edit
logging:
  file_path: "unipkg_audit.log"
  console_style: "JSON"
  async_logging: false
Never email or publicly share raw logs containing secrets or sensitive data.

Troubleshooting
Problem	Solution/Next Step
PluginNotFound	Check that plugin is enabled and installed.
Permission errors	Use a clean container or check file permissions.
Network/SSL issues	Set offline: true in config to use cached data.
SBOM or log verification fails	Check for file corruption, missing keys, mismatched versions.
Unexpected errors	Increase logging: unipkg --verbose <command>

Support & Contribution
Help/Bug reports:
Open issues at https://github.com/yourorg/upm/issues

Contributing:
See CONTRIBUTING.md

All new plugins must include tests, SBOMs, and pass security review

Every plugin must include the sandbox entrypoint (see PLUGINS.md)

Always update UPM, dependencies, and plugins

Review all configuration/security warnings before production

End of USAGE.md