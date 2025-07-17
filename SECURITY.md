# SECURITY POLICY — Unexpected Innovations Toolkit

_Last updated: 2025-07-16_

This repository is a toolkit of advanced open-source developer tools (each in its own subdirectory).  
**Each tool is designed, tested, and maintained independently.**

---

## 🛡️ Threat Model & Scope

**This repo contains multiple tools, each with its own codebase, threat model, and security documentation.**  
- **Default policy:** Every tool is process-isolated and should be treated as a standalone application.
- **No shared security guarantees:** Security properties, sandboxes, and mitigations are tool-specific.  
- **Your risk = the tool’s risk:** Only trust tools you have reviewed, tested, and understand.

> **WARNING:** Some tools can access files, networks, or execute untrusted plugins/code.  
> **Never run any tool from this repo in a production or sensitive environment without first reading that tool’s `SECURITY.md` and doing your own audit.**

---

## 🔗 Per-Tool Security Docs

- **UPM**: [`upm/SECURITY.md`](upm/SECURITY.md)  
- **(Cache system, debugger, etc.—coming soon)**

Each tool has its own `SECURITY.md` covering:
- Threat model, attack surface, and mitigations
- Sandboxing and process isolation model
- Disclosure, audit logging, and supply chain policies
- Known limitations and recommendations

---

## 🚨 Vulnerability Reporting

**If you find a security issue:**

- **DO NOT** file a public issue.
- Contact: [security@unexpectedinnovations.com](mailto:security@unexpectedinnovations.com)  
- Optionally, use GitHub’s [private security advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability).

We will acknowledge all reports within 72 hours and follow up promptly.

---

## 🏷️ Best Practices

- Run all tools in a container, VM, or throwaway environment until you have audited the code and dependencies.
- Never use untrusted plugins or templates with any included tool.
- Enable audit logging where possible and review logs regularly.
- Always follow least-privilege: avoid running tools as root or with unnecessary system privileges.

---

## 📚 References

- [UPM Security Policy](upm/SECURITY.md)
- [PLUGINS.md](PLUGINS.md) (for plugin/process isolation policies)
- [RELEASE.md](RELEASE.md) (release signing/SBOM policy)
- Each tool’s own `SECURITY.md` for detailed information

---

**This is a living document and will evolve as new tools are added to the toolkit.  
Security is everyone’s responsibility—if in doubt, ask.**
