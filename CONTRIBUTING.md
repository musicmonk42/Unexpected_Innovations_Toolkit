# Contributing to the Unexpected Innovations/Legal Tender Toolkit

Thank you for considering a contribution!  
This toolkit is a collection of advanced, auditable, and security-focused developer tools—each with its own subdirectory and documentation.

> **This CONTRIBUTING guide covers the overall repository.  
> Each individual tool may have its own `CONTRIBUTING.md` and additional rules—see that tool’s subfolder.**

---

## 🧰 Adding a New Tool

**To propose or add a new tool, you must:**

1. **Create a subdirectory:**  
   - Name it clearly (e.g. `upm/`, `cache/`, `timetravel_debugger/`).
2. **Include required files:**  
   - `README.md` (high-level overview, usage, design, status)
   - `SECURITY.md` (threat model, security model, known limitations)
   - `CONTRIBUTING.md` (if it has tool-specific contribution rules—optional but encouraged)
   - `LICENSE` (if not MIT or differs from repo-wide license)
   - Tests (minimum: unit, integration, and any required for sandbox/process safety)
3. **Follow naming and structure conventions:**  
   - Use snake_case for directories and filenames.
   - Tool code goes in its own subdir, not in the root.
   - All scripts must be documented.
4. **Document all APIs and CLI commands.**

---

## 🛡️ Quality, Security & Sandboxing

- **Every tool must:**  
  - Pass all its own tests (unit/integration/security).
  - Document its API, CLI, and configuration.
  - Default to the strictest possible security/sandbox mode.
  - Disclose all known limitations and security caveats in `SECURITY.md`.
  - Use process isolation/sandboxing where feasible (see UPM/PLUGINS.md for example).
  - Log all sensitive or risky actions for audit.

- **Supply chain security:**  
  - SBOMs (e.g., via `syft` or `cyclonedx`) are encouraged for all Python projects.
  - Signed commits and reproducible builds are preferred but not required.
  - Disclose all external dependencies in your `README.md`.

---

## 🚦 Submitting Your Contribution

1. **Fork this repo and create a branch** for your feature/fix/tool.
2. **Test your changes**—run all tool-level and repo-level tests.
3. **Open a Pull Request**  
   - Describe what you’ve added, and why.
   - List which tests/docs you’ve added or updated.
   - If your tool uses a different license, note this clearly.

4. **Peer review**  
   - All PRs require review by a maintainer.
   - Security and sandboxing are prioritized in reviews.

---

## 🔗 Per-Tool CONTRIBUTING

Some tools have their own `CONTRIBUTING.md` (for example, UPM: [`upm/CONTRIBUTING.md`](upm/CONTRIBUTING.md)).  
If you’re working on a specific tool, always read and follow that file as well.

---

## 📬 Questions & Feedback

- General questions: (https://github.com/UnexpectedInnovations/toolkit/discussions)
- Security concerns: [brian@legaltenderfinancial.com](mailto:brian@legaltenderfinancial.com)
- For per-tool issues, use that tool’s issue tracker (if it exists), or tag the tool name in your issue.

---

**Thank you for helping build a world-class open toolkit—secure, auditable, and useful for everyone.**
