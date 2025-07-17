# UPM Plugin System

**Universal Package Manager (UPM) Plugin Architecture & Authoring Guide**  
_Last updated: 2025-07-16_

---

> ⚠️ **SECURITY WARNING**  
> UPM plugins execute arbitrary code and, while **now always run in a sandboxed subprocess by default**, are NOT a full OS sandbox on all platforms.  
> Only install, develop, or run plugins you trust. Always verify plugin signatures and audit plugin source code.  
> On Linux, subprocess boundaries are strong and can be combined with seccomp for syscall filtering. On Windows/macOS, process isolation is weaker—**never use untrusted plugins outside a container or VM.**  
>  
> **Every plugin must include the sandbox entrypoint block at the end of the file. See below.**

---

## 📖 Overview

- **Purpose:** Extend UPM to support new package managers/tools via the `EcosystemPlugin` base class (`upm/plugins/base.py`).
- **Architecture:**
    - Standardized async interface for all plugin operations
    - **Secure process isolation (default: subprocess for every plugin call)**
    - Policy enforcement from `.unipkgpolicy.yaml`
    - Observability: built-in metrics and event hooks for every plugin action

---

## 📦 Built-in Plugins

- **pip.py** (Python)
- **npm.py** (Node.js)
- **cargo.py** (Rust)
- _(See the plugins folder for more examples)_

---

## 🚀 Creating a Plugin

### 1. Prerequisites

- Python 3.8+ and UPM installed in editable mode:
    ```sh
    pip install -e .
    pip install -r requirements-dev.txt
    ```
- Review `CONFIGURATION.md` and `SECURITY.md`.

### 2. Plugin Structure

- Place your plugin file in `upm/plugins/` (e.g., `myplugin.py`)
- Inherit from `EcosystemPlugin`
- Implement all abstract methods (see next section)

#### Minimal Plugin Stub

```python
from upm.plugins.base import EcosystemPlugin, PluginOperationError, PluginPolicyViolation
import asyncio

class MyPlugin(EcosystemPlugin):
    async def install(self, name: str, version: str = None, verbose: bool = False, dry_run: bool = False) -> bool:
        self._check_policy("install", name, version)
        # implement logic
        return True

    async def uninstall(self, name: str, verbose: bool = False, dry_run: bool = False) -> bool:
        # implement logic
        return True

    async def upgrade(self, name: str, version: str = None, verbose: bool = False, dry_run: bool = False) -> bool:
        # implement logic
        return True

    async def list_installed(self) -> list:
        # implement logic
        return []

    async def doctor(self) -> bool:
        # implement logic (e.g., run ecosystem's audit tool)
        return True

    async def suggest(self, query: str) -> list:
        # implement logic
        return []

    async def auto_fix(self) -> bool:
        # implement logic
        return True
3. Mandatory: Plugin Sandbox Entrypoint
All plugins MUST include the following entrypoint block at the end of the file. This enables secure subprocess isolation.
Plugins missing this will NOT run under UPM.

python
Copy
Edit
if __name__ == "__main__":
    import sys, json, asyncio, traceback
    try:
        payload = json.loads(sys.argv[1])
        class_name = payload["class_name"]
        cls = globals()[class_name]
        plugin = cls(**payload["init_args"])
        method_name = payload["run_args"]["method_name"]
        args = payload["run_args"].get("args", [])
        kwargs = payload["run_args"].get("kwargs", {})
        method = getattr(plugin, method_name)
        if asyncio.iscoroutinefunction(method):
            output = asyncio.run(method(*args, **kwargs))
        else:
            output = method(*args, **kwargs)
        print(json.dumps(output))
    except Exception as e:
        err_json = json.dumps({
            "error": True,
            "message": str(e),
            "traceback": traceback.format_exc()
        })
        print(err_json, file=sys.stderr)
        sys.exit(1)
This enables process isolation and safe error propagation.

Do not print to stdout anywhere else in your plugin.

See SECURITY.md for details.

4. Registering and Signing Plugins
Entry Point:
Add your plugin to setup.py under entry_points['upm.plugins']:

ini
Copy
Edit
[options.entry_points]
upm.plugins =
    myplugin = upm.plugins.myplugin:MyPlugin
Manifest:
Run:

sh
Copy
Edit
python scripts/generate_plugin_manifest.py
This updates plugin_manifest.json with a SHA256 hash for integrity.

Signature Verification:
Run:

sh
Copy
Edit
python scripts/verify_plugin_signatures.py
This ensures all plugins are authentic before loading.

5. Security Considerations
Process Isolation: All plugins run in subprocesses.
This provides strong safety, but is not a full OS sandbox.
For untrusted plugins, use containers or VMs for extra defense.

Policy Enforcement:
Always enforce blocked_packages, allowed_packages, and pinned_versions from .unipkgpolicy.yaml.

Sensitive Data:
Use redact_secrets() from logging_utils.py for all sensitive values in logs.

Vulnerability Checks:
Implement doctor() to call your ecosystem's audit tools (e.g., pip-audit, npm audit).

Platform Caveats:
On Windows/macOS, plugin subprocesses are not as isolated as on Linux.
See SECURITY.md for limitations.

Plugin Trust Policy Table
Plugin Source	Allowed by Default?	For Production?	Signature/Hash Required?
Official Repository	Yes	Yes	Yes
3rd-party (unsigned)	No	No	No
3rd-party (signed)	User opt-in	Only if fully audited	Yes

6. Testing Plugins
Create tests in tests/ (e.g., test_myplugin.py) using pytest and conftest.py.

Test ALL abstract methods, policy edge cases, and failure paths.

Test for process isolation:
Launch plugin via the subprocess/sandbox runner and assert correct behavior.
Example test stub:

python
Copy
Edit
import pytest
from upm.plugins.myplugin import MyPlugin

@pytest.mark.asyncio
async def test_install_success(mock_policy, temp_project_root, temp_cache_dir, mock_subprocess_run):
    plugin = MyPlugin(temp_project_root, temp_cache_dir, mock_policy)
    result = await plugin.install("safe-pkg", verbose=True)
    assert result is True
    assert plugin.metrics["install_success_total"] == 1

@pytest.mark.asyncio
async def test_install_policy_blocked(mock_policy, temp_project_root, temp_cache_dir):
    plugin = MyPlugin(temp_project_root, temp_cache_dir, mock_policy)
    with pytest.raises(PluginPolicyViolation):
        await plugin.install("blocked-pkg")
Run coverage:

sh
Copy
Edit
pytest tests/test_myplugin.py --cov=upm.plugins.myplugin
7. Metrics and Events
Always update your metrics dictionary (install_success_total, plugin_errors_total, etc.)

Implement publish_event() for integration with Kafka, AWS EventBridge, etc.

python
Copy
Edit
await self.publish_event("install", {"package": name, "version": version, "success": True})
8. Best Practices
Always enable process isolation (default: sandboxed subprocess).

Raise PluginOperationError or PluginPolicyViolation for all failures; log via AUDIT_LOGGER.

Respect all .unipkgrc settings (e.g., security.encrypt_data, logging.async_logging)

Document every method and class; update README.md and USAGE.md if adding a new ecosystem.

Aim for 100% coverage on critical logic; use conftest.py fixtures.

Every plugin PR must update the manifest and pass all tests.

Plugins must never bypass core policy, sandbox, or logging.

9. Example: Minimal Gem Plugin
python
Copy
Edit
from upm.plugins.base import EcosystemPlugin, PluginOperationError
import asyncio

class GemPlugin(EcosystemPlugin):
    async def install(self, name, version=None, verbose=False, dry_run=False):
        self._check_policy("install", name, version)
        if dry_run:
            print(f"[Dry run] Installing gem {name}{'@' + version if version else ''}")
            return True
        try:
            cmd = ["gem", "install", name]
            if version:
                cmd.extend(["--version", version])
            await self._run_my_cmd(cmd, verbose)
            self.metrics["install_success_total"] += 1
            await self.publish_event("install", {"package": name, "version": version})
            return True
        except Exception as e:
            self.metrics["install_failure_total"] += 1
            raise PluginOperationError(f"Failed to install {name}: {e}")

    async def _run_my_cmd(self, cmd, verbose):
        result = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await result.communicate()
        if result.returncode != 0:
            raise PluginOperationError(f"Gem command failed: {stderr.decode()}")
10. Resources
Configuration: CONFIGURATION.md

Testing: CONTRIBUTING.md

Security: SECURITY.md

Logging & Events: LOGGING.md

API & Usage: API.md, USAGE.md

✅ Checklist for Plugin Submission
 Inherit from EcosystemPlugin

 Implement all required abstract methods (install, uninstall, upgrade, list, doctor, suggest, auto_fix, etc.)

 Include the sandbox entrypoint block at the end of the file (see above)

 Robustly handle policy and error cases

 Use process isolation and redact secrets in logs

 Provide full test coverage (unit, integration, negative, process isolation)

 Document your plugin and update core docs as needed

 Run python scripts/generate_plugin_manifest.py

 Pass CI for pytest, flake8, mypy

End of PLUGINS.md