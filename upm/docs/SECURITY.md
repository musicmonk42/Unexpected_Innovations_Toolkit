# SECURITY.md

## Security Overview

The UPM Secure Plugin Entrypoint is designed for environments where **plugin execution must never compromise the host or user data**.  
It uses defense-in-depth: **strict whitelisting, argument validation, output capture, audit logging, and support for container isolation** (Docker).

---

## Threat Model

This project assumes a potentially hostile plugin codebase or untrusted input. The architecture mitigates:

- **Malicious or buggy plugin code:**  
  - Only explicitly whitelisted classes and methods are callable.
  - Plugin execution is isolated (via Docker or subprocess).
  - Arguments are strictly schema-validated before any plugin code runs.
- **Input attacks:**  
  - No arbitrary code or method invocation.
  - No direct filesystem or network access beyond what the plugin is granted inside its container/sandbox.
- **Supply chain:**  
  - All plugins are registered explicitly in the config.
  - Plugin module paths and method names are never constructed from user input.

---

## Security Mechanisms

### 1. **Plugin Whitelist / Allowed Methods**
- Only plugin classes and methods declared in the config can ever be called.
- No dynamic loading, string eval, or “guessing” of plugin code is possible.

### 2. **Argument Schema Validation**
- Every plugin call’s arguments are validated against a strict [JSON Schema](https://json-schema.org/).
- Invalid or malformed input is rejected with a clear JSON error.

### 3. **Output and Error Capture**
- All plugin stdout/stderr, errors, and tracebacks are captured and included in the structured JSON response.
- No unstructured output or leaked error messages.

### 4. **Audit Logging**
- Every invocation (success or failure) is logged with:
  - ISO8601 UTC timestamp
  - Hostname
  - Process ID (PID)
  - Globally unique `request_id` (UUID)
  - Full invocation details and outcome
- Log output is to both stdout and a persistent file (`entrypoint.log`).

### 5. **Sandboxing and Containerization**
- **Recommended:** Run entrypoint in a minimal Docker container for OS-level isolation.
- No network access by default (`--network=none` for Docker runs).
- Container runs as a non-root user (`nobody:nogroup` or equivalent).
- Filesystem is mounted read-only except for log/output volumes.
- **Fallback:** If Docker is not available, a subprocess is used (less secure, audit logged).

### 6. **Config Safety**
- Only plugin classes/methods listed in `upm_config.json` or the default config are callable.
- It is recommended to store the config in a secure, version-controlled repository, and use code review for changes.

---

## Security Best Practices

- **Always run plugins in the most restrictive environment possible (prefer Docker).**
- **Never whitelist third-party plugins without review.**
- Review plugin code before approving/adding to config.
- Rotate log files and monitor for anomalies (see Audit section).
- Keep the plugin config (`upm_config.json`) under strict access control.
- Do not expose the entrypoint to the public internet without additional authentication and rate limiting.
- Keep dependencies up-to-date and monitor for vulnerabilities.

---

## Audit & Monitoring

- **All calls and errors are logged with traceability (`request_id`).**
- Review `entrypoint.log` for repeated errors, failed calls, or unexpected plugin activity.
- Consider shipping logs to a central SIEM or monitoring system for alerting.
- Each plugin call’s output includes the request ID for easy correlation.

---

## Vulnerability Reporting / Responsible Disclosure

If you discover a security issue:

1. **Do not** file a public GitHub issue.
2. **Email the maintainers directly** at [YOUR-SECURITY-CONTACT@example.com].
3. Include a detailed description, your contact info, and steps to reproduce if possible.
4. We will acknowledge receipt within 48 hours and coordinate a response.

---

## Future/Advanced (optional enhancements)

- **Digital signature verification** for plugin code (if used in high-security environments).
- **Resource limits** (CPU, memory, execution time) enforced at the container level.
- **SELinux/AppArmor** profiles for even tighter host OS policy.
- **Automated code scanning** for all plugin submissions.

---

## References

- [JSON Schema Validation](https://json-schema.org/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

---

**This project is designed for maximum transparency, auditability, and defense-in-depth.**  
If you have security feedback or would like to contribute additional hardening, please submit a pull request or contact the maintainers.
