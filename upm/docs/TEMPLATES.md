# UPM Project Templates: Structure, Customization, and Security

**Universal Package Manager (UPM) — Project Templates**  
_Last updated: 2025-07-16_

---

> ⚠️ **SECURITY WARNING**  
> UPM templates can write arbitrary files and code.  
> Never use templates from untrusted sources without review.  
> Templates with dangerous extensions or risky patterns are **blocked by default**.  
> For untrusted or custom templates, always run UPM in a container or VM and enable encryption and audit logging.  
> All template operations are logged, with violations recorded as CRITICAL.

---

## 🏗️ Template Structure

- **Format:** YAML dictionaries mapping output filenames to file content.
- **Storage:** `upm_templates/<category>/<template>.yaml` (e.g., `upm_templates/frontend/react-basic.yaml`)
- **Naming:** `<category>__<template>__<version>` (e.g., `frontend__react-basic__1.0.0`)
- **Content Types:**  
    - String (with `{placeholders}` for runtime substitution)
    - Structured data (dicts/lists for YAML/JSON/TOML; auto-serialized)

#### **Example Template: upm_templates/python-project.yaml**

```yaml
version: "1.0.0"
files:
  main.py: |
    # {project_name} by {author}
    def main():
        print("Hello from {project_name}!")
  README.md: |
    # {project_name}
    A Python project initialized by UPM.
    Author: {author}
  requirements.txt: |
    requests>=2.32.4
    typer^0.9.0
  config.yaml:
    name: "{project_name}"
    author: "{author}"
    settings:
      debug: true
      log_level: "INFO"
  .gitignore: |
    .unipkg_env/
    *.lock
    dist/
💡 Dynamic Placeholders
Supported: {project_name}, {author}

Set via CLI: --project-name, --author (default: current system user)
Note: Placeholders only interpolate in string values.

CLI Example:

sh
Copy
Edit
unipkg init python-project my-app --project-name "MyApp" --author "Jane Doe"
🔖 Template Versioning

Every template includes a version: field (SemVer).
Reference templates as <category>__<template>__<version>

CLI:

sh
Copy
Edit
unipkg init python-project my-app --version 1.0.0
🔒 Template Security & Supply Chain

1. Extension/Pattern Scanning
File Type	Action
.sh, .py, .bat, .cmd, .exe, ...	Warn + manual approval required
Dangerous code (rm -rf, eval, `curl	sh`)

All violations are logged and surfaced to user as CRITICAL.

Example warning/log output:

json
Copy
Edit
{"operation": "init", "file": "dangerous.sh", "reason": "dangerous_keyword"}
2. Best Practices
Use official templates or those from trusted, signed partners only.

Always review YAML/contents before use.

For untrusted sources:

Run UPM in a container/VM

Enable encryption (security.encrypt_data: true)

See CONFIGURATION.md for more.

3. Logging & Compliance
All template processing is logged (async logging recommended for scale).

All violations/blocks are CRITICAL in audit log and CLI.

⚠️ Requirements Table

Feature	Requirement
TOML templates	toml Python package
Encryption	cryptography package
Logging scale	logging.async_logging in .unipkgrc

🔐 Template Trust Policy

Template Source	Allowed by Default?	For Production?	Manual Review Needed?
Official UPM Repo	Yes	Yes	No
Trusted Partner Repo	Yes (if signed)	Yes	Recommended
Community/3rd-party	No	No	Yes

🚦 Validating Templates (Quick Guide)

sh
Copy
Edit
unipkg init <category>__<template>__<version> my-project --project-name "MyProj" --author "Alex Smith"
unipkg doctor
unipkg log-decrypt unipkg_audit.log
# Review for any "dangerous" warnings before using output
📚 Creating & Using Custom Templates

Create: YAML in upm_templates/<category>/ (e.g., web/my-app.yaml)

Include: version: and all files/contents, using placeholders as needed.

Test:

sh
Copy
Edit
unipkg init <category>__<template>__<version> my-project --project-name "MyProj" --author "Alex Smith"
unipkg doctor
Contribute:
See CONTRIBUTING.md; write tests in test_project_init.py.

✅ Checklist for Template Contribution

 All filenames and extensions reviewed for safety

 No dangerous shell/code patterns (rm -rf, curl | sh, etc)

 Version is set (SemVer)

 Placeholders documented/used correctly

 Output files tested with CLI (unipkg init, doctor)

 Audit logs checked for warnings

 Tests added/updated in test_project_init.py

📖 Example Workflow

sh
Copy
Edit
# Initialize new Python project from a specific template version
unipkg init python-project my-app --version 1.0.0 --project-name "MyApp" --author "Jane Doe"

# Verify template safety and output
unipkg doctor

# Review audit logs for any issues
unipkg log-decrypt unipkg_audit.log
🔗 References

CONFIGURATION.md: Encryption, logging

LOGGING.md: Audit log usage

CONTRIBUTING.md: Template/test workflow

SECURITY.md: Supply chain security

PLUGINS.md: Extending UPM, process isolation

RELEASE.md: Release/SBOM signing

API.md: Programmatic template init

README.md: Overview, quick start

End of TEMPLATES.md