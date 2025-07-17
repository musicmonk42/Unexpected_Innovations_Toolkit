# Contributing to UPM Secure Plugin Entrypoint

Thank you for your interest in contributing to this project!  
This system is designed for security, auditability, and high reliability.  
**Every contribution—especially plugins—must meet strict standards.**

---

## Table of Contents

- [How to Propose a Plugin or Feature](#how-to-propose-a-plugin-or-feature)
- [Plugin Coding Requirements](#plugin-coding-requirements)
- [Updating the Whitelist/Config](#updating-the-whitelistconfig)
- [Testing Your Contribution](#testing-your-contribution)
- [Code Style and Guidelines](#code-style-and-guidelines)
- [Pull Request Checklist](#pull-request-checklist)
- [Reporting Bugs or Security Issues](#reporting-bugs-or-security-issues)
- [Community Standards](#community-standards)

---

## How to Propose a Plugin or Feature

1. **Open an issue** describing your plugin or feature idea.
2. Wait for feedback from maintainers (for security/fit review).
3. Once approved, you can submit a pull request.

**Plugins will not be accepted unless:**
- They meet the security and code guidelines.
- They pass all automated and manual reviews.
- They serve a real user or organizational need.

---

## Plugin Coding Requirements

- **Plugin class must be listed in the config (`upm_config.json`)** and imported via a fully-qualified Python module path.
- **Init signature must include (optionally):**
  - `project_root`, `cache_dir`, `policy`, `fernet_lib` (these may be unused).
- **Methods must only include those whitelisted in config.**  
  No magic, dynamic, or hidden methods.
- **Return values must be JSON serializable.**
- **Support both sync and async methods if possible.**
- **Expose one or more introspection methods:**  
  - `version`, `info`, `meta`, or `__introspect__`
- **No network, filesystem, or subprocess access unless required and documented.**
- **All side-effects must be auditable via logs or returned output.**

---

## Updating the Whitelist/Config

- All plugins and allowed methods **must** be added to `upm_config.json` (see example in README).
- **Never add plugins to the whitelist that you have not reviewed.**
- Each method entry must be explicitly listed for each plugin.

---

## Testing Your Contribution

- **All new plugins/methods must have corresponding tests.**
- Tests must cover:
  - Success and failure cases (including malformed input)
  - All whitelisted methods and introspection
  - Output capture (stdout, stderr, JSON contract)
  - Logging/audit trace (request ID, timestamps, etc.)
- Run the test suite locally with:
  ```bash
  pytest
If you are adding a plugin, include a mock module and usage example for reviewers.

Code Style and Guidelines
PEP8 for Python code.

Write clear, well-documented code with docstrings for every public method/class.

Use typed signatures whenever possible.

Avoid “clever” metaprogramming or dynamic imports.

Ensure all exceptions are handled and returned as JSON errors.

Pull Request Checklist
Before submitting, make sure you:

 Describe the purpose and context of your change.

 Have updated or added tests as required.

 Updated documentation (README, SECURITY.md, config examples) if your change impacts usage or security.

 Have run pytest and fixed any failures.

 Have rebased onto the latest main branch.

Reporting Bugs or Security Issues
For non-security bugs:
Open an issue with as much detail as possible.

For security vulnerabilities:
DO NOT file a public issue.
Email the maintainers at [YOUR-SECURITY-CONTACT@example.com].

Community Standards
Be respectful, collaborative, and constructive.

Reviewers may request changes or reject plugins/features for security, maintainability, or scope reasons.

No hate speech, harassment, or disruptive behavior is tolerated.

Thank you for helping make UPM Secure Plugin Entrypoint safe and reliable for everyone!