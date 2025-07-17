# upm/plugins/cargo.py

import os
import json
import subprocess
import asyncio
import re
import time
import aiohttp
import sys
import shutil
from typing import Dict, List, Optional, Tuple, Any

# Conditional imports
try:
    import toml
    _TOML_AVAILABLE = True
except ImportError:
    toml = None
    _TOML_AVAILABLE = False
    sys.stderr.write("CRITICAL ERROR: 'toml' library is not installed. Cargo plugin will not function without it.\n")

# Import from other modules
from upm.plugins.base import EcosystemPlugin, PluginOperationError, PluginPolicyViolation # FIX: Removed self-referential import of CargoPlugin
from upm.logging_utils import AUDIT_LOGGER

# --- Constants for Security ---
SAFE_CARGO_CRATE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")
DANGEROUS_CARGO_ENV_VARS = ["CARGO_TARGET_DIR", "CARGO_HOME", "RUSTC", "RUSTFLAGS"]
SHELL_INJECTION_CHARS_REGEX = re.compile(r'[;&|`$()]')


class CargoPlugin(EcosystemPlugin):
    """
    UPM Ecosystem Plugin for managing Rust packages via Cargo.
    """

    PLUGIN_API_VERSION: str = "1.0.0"
    DANGEROUS_CARGO_ENV_VARS = DANGEROUS_CARGO_ENV_VARS

    def __init__(self, project_root: str, cache_dir: str, policy: Dict[str, Any], fernet_lib: Any = None): # FIX: Add fernet_lib here
        super().__init__(project_root, cache_dir, policy, fernet_lib=fernet_lib) # FIX: Pass fernet_lib to super
        if not _TOML_AVAILABLE:
            raise PluginOperationError("TOML library is required for Cargo operations. Please install it ('pip install toml').")
        
        self.metrics["cargo_binary_calls_total"] = 0
        self.cargo_version: Optional[str] = None
        self._check_cargo_command()

    def _check_cargo_command(self):
        """Checks if the 'cargo' command is available and executable."""
        if os.environ.get("UPM_SKIP_CARGO_CHECK") == "1":
            self.cargo_version = "mock_cargo 1.70.0"
            return
            
        try:
            result = subprocess.run(["cargo", "--version"], capture_output=True, text=True, check=True, timeout=5)
            self.cargo_version = result.stdout.strip()
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            AUDIT_LOGGER.critical("Cargo initialization failed: 'cargo' command not found or not functional.", exc_info=True)
            raise PluginOperationError(f"'cargo' command not found or not functional. Ensure the Rust toolchain is installed. Error: {e}")

    def _validate_package_name(self, name: str):
        """Raises PluginOperationError if the package name is invalid."""
        if not SAFE_CARGO_CRATE_NAME_REGEX.match(name):
            error_msg = f"Invalid Cargo crate name '{name}'. Name contains disallowed characters or format."
            AUDIT_LOGGER.critical(f"CargoPlugin: {error_msg}", extra={"package_name": name})
            raise PluginOperationError(error_msg)

    async def _run_cargo_command(self, cmd: List[str], verbose: bool = False, **kwargs: Any) -> subprocess.CompletedProcess:
        """Internal helper to run Cargo commands with security considerations."""
        for arg in cmd:
            if SHELL_INJECTION_CHARS_REGEX.search(arg):
                self.metrics["plugin_errors_total"] += 1
                raise PluginOperationError(f"Potential shell injection detected in argument: '{arg}'")
        
        full_cmd: List[str] = ["cargo"] + cmd
        self.metrics["cargo_binary_calls_total"] += 1

        sanitized_env = os.environ.copy()
        for var in self.DANGEROUS_CARGO_ENV_VARS:
            if var in sanitized_env:
                del sanitized_env[var]
                AUDIT_LOGGER.info(f"CargoPlugin: Removed potentially dangerous env var '{var}' for subprocess.", extra={"variable": var})

        try:
            if verbose: print(f"CargoPlugin: Running command: {' '.join(full_cmd)}")
            result = await asyncio.to_thread(
                subprocess.run,
                full_cmd, capture_output=True, text=True, check=True,
                cwd=self.project_root, shell=False, env=sanitized_env, **kwargs
            )
            return result
        except subprocess.CalledProcessError as e:
            error_message = f"Cargo command '{' '.join(e.cmd)}' failed with exit code {e.returncode}. Stderr: {e.stderr.strip()}"
            self.metrics["plugin_errors_total"] += 1
            AUDIT_LOGGER.error(f"Cargo command '{' '.join(e.cmd)}' failed.", exc_info=True)
            raise PluginOperationError(error_message) from e
        except FileNotFoundError as e:
            error_message = "'cargo' command not found. Ensure the Rust toolchain is installed and in your PATH."
            self.metrics["plugin_errors_total"] += 1
            AUDIT_LOGGER.critical("Cargo command not found.", exc_info=True)
            raise PluginOperationError(error_message) from e
        except subprocess.TimeoutExpired as e:
            error_message = f"Cargo command '{' '.join(e.cmd)}' timed out."
            self.metrics["plugin_errors_total"] += 1
            AUDIT_LOGGER.error(error_message, exc_info=True)
            raise PluginOperationError(error_message) from e

    async def _install_impl(self, name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool:
        self._validate_package_name(name)
        self._check_policy("install", name, version_constraint)
        cmd = ["add", name]
        if version_constraint:
            cmd.extend(["--vers", version_constraint])
        await self._run_cargo_command(cmd, verbose)
        self.metrics["install_success_total"] += 1
        return True

    async def _uninstall_impl(self, name: str, verbose: bool = False) -> bool:
        self._validate_package_name(name)
        cmd = ["rm", name]
        await self._run_cargo_command(cmd, verbose)
        self.metrics["uninstall_success_total"] += 1
        return True

    async def _upgrade_impl(self, name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool:
        self._validate_package_name(name)
        cmd = ["update", "--package", name]
        await self._run_cargo_command(cmd, verbose)
        return True

    async def _list_installed_impl(self, verbose: bool = False) -> Dict[str, str]:
        cargo_lock_path = os.path.join(self.project_root, "Cargo.lock")
        if not os.path.exists(cargo_lock_path):
            return {}
        try:
            with open(cargo_lock_path, 'r', encoding="utf-8") as f:
                lock_data = toml.load(f)
            packages = {pkg.get("name"): pkg.get("version") for pkg in lock_data.get("package", []) if pkg.get("name") and pkg.get("version")}
            return packages
        except Exception as e:
            AUDIT_LOGGER.error("Failed to read or parse Cargo.lock.", exc_info=True)
            # FIX: Preserve the original exception cause
            raise PluginOperationError(f"Failed to read or parse Cargo.lock: {e}") from e

    async def _doctor_impl(self, verbose: bool = False) -> List[str]:
        return ["Plugin is healthy."]

    async def _fetch_features_impl(self, package_name: str, package_version: str) -> Dict[str, Any]:
        if self.policy.get("offline"):
            raise PluginOperationError("Cannot fetch package metadata in offline mode.")
        AUDIT_LOGGER.info(f"Fetching features for Cargo crate: {package_name}@{package_version} (placeholder).")
        return {'dependency_age_days': 365, 'num_known_cves_past_year': 0, 'maintainer_activity_score': 5.0, 'transitive_dependency_count': 1, 'has_install_scripts': 0, 'license_is_permissive': 1}
    
    async def _search_impl(self, query: str, verbose: bool = False, **kwargs) -> List[Dict[str, str]]: self._validate_package_name(query); return []
    async def _outdated_impl(self, verbose: bool = False) -> Dict[str, str]: return {}
    async def _suggest_impl(self, name: str, verbose: bool = False) -> List[Dict[str, str]]: return []
    async def _auto_fix_impl(self, name: str, verbose: bool = False, suggested_version: Optional[str] = None) -> Tuple[bool, str]:
        self._validate_package_name(name)
        await self._upgrade_impl(name, suggested_version, verbose)
        return True, "Successfully upgraded crate."
    async def _export_native_manifest_impl(self, packages: Dict[str, str], verbose: bool = False) -> None: pass
    async def _import_native_manifest_impl(self, verbose: bool = False) -> List[Dict[str, str]]: return []
    async def _collect_metrics_impl(self, verbose: bool = False) -> Dict[str, Any]: return self.metrics
    async def _publish_event_impl(self, event_type: str, event_data: Dict[str, Any], verbose: bool = False) -> None: pass
    async def _prune_impl(self, package_name: str, verbose: bool = False) -> bool:
        await self._uninstall_impl(package_name, verbose)
        return True

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

        # Success: Print only the result JSON to stdout
        print(json.dumps(output))

    except Exception as e:
        # Print error info as JSON to stderr (never stdout!)
        err_json = json.dumps({
            "error": True,
            "message": str(e),
            "traceback": traceback.format_exc()
        })
        print(err_json, file=sys.stderr)
        sys.exit(1)