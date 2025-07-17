# upm/plugins/pip.py

import os
import json
import subprocess
import asyncio
import aiohttp
import re
import time
import sys
import shutil
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone

# UPM Core Imports
from upm.plugins.base import EcosystemPlugin, PluginOperationError, PluginPolicyViolation
from upm.logging_utils import AUDIT_LOGGER

# --- Conditional Imports for Optional Features (from original base.py context for Pydantic PolicyModel validation) ---
try:
    from pydantic import BaseModel, Field, ValidationError, constr
    _PYDANTIC_AVAILABLE = True
except ImportError:
    # Define dummy classes/values if pydantic is not available to avoid NameErrors in class definitions
    BaseModel, Field, ValidationError, constr = object, object, None, None # Ensure these are defined
    _PYDANTIC_AVAILABLE = False
    sys.stderr.write("Warning: 'pydantic' not installed. Policy validation will be partially disabled for PipPlugin.\n")


class PipPlugin(EcosystemPlugin):
    """
    UPM Ecosystem Plugin for managing Python packages via pip.
    """
    PLUGIN_API_VERSION: str = "1.0.0"

    def __init__(self, project_root: str, cache_dir: str, policy: Dict[str, Any], fernet_lib: Any = None): # FIX: Add fernet_lib here
        super().__init__(project_root, cache_dir, policy, fernet_lib=fernet_lib) # FIX: Pass fernet_lib to super
        self.venv_path = os.path.join(project_root, ".venv")
        # _get_python_executable no longer takes preferred_python, as it always uses sys.executable
        self.python_cmd = self._get_python_executable() 
        self.pip_cmd = [self.python_cmd, "-m", "pip"]
        # IMPORTANT: asyncio.run() is REMOVED from __init__.
        # The venv setup (which is an async operation) should be awaited externally,
        # e.g., by the PluginManager in UPM core, or by async test fixtures.

    def _get_python_executable(self) -> str:
        """Determines the Python executable to use for venv creation. Uses current Python."""
        return sys.executable

    async def _ensure_venv_sync(self):
        """Ensures a virtual environment exists and is up-to-date. This is an async method."""
        if not os.path.exists(self.venv_path):
            AUDIT_LOGGER.info(f"Creating virtual environment at: {self.venv_path}")
            # Correctly form the command list for subprocess.run
            cmd = [self.python_cmd, "-m", "venv", self.venv_path]
            try:
                await asyncio.to_thread(subprocess.run, cmd, check=True, capture_output=True, text=True, timeout=60)
            except subprocess.CalledProcessError as e:
                AUDIT_LOGGER.error(f"Failed to create virtual environment: {e.stderr}")
                raise PluginOperationError(f"Failed to create virtual environment: {e.stderr}")
            except FileNotFoundError:
                raise PluginOperationError("Python venv module not found. Ensure Python is installed correctly.")
            except subprocess.TimeoutExpired:
                raise PluginOperationError("Virtual environment creation timed out.")
        
        AUDIT_LOGGER.info(f"Ensuring pip is up-to-date in venv: {self.venv_path}")
        try:
            # Pass only the specific pip arguments to _run_pip_cmd
            await self._run_pip_cmd(["install", "--upgrade", "pip", "setuptools", "wheel"])
        except Exception as e:
            AUDIT_LOGGER.warning(f"Failed to upgrade pip in venv: {e}")

    def _validate_package_name(self, name: str):
        """Rudimentary validation to prevent shell injection in package names."""
        if not re.match(r"^[a-zA-Z0-9._-]+$", name):
            raise PluginOperationError(f"Invalid package name: '{name}'. Contains disallowed characters.")

    async def _run_pip_cmd(self, cmd_args: List[str], verbose: bool = False, **kwargs: Any) -> subprocess.CompletedProcess:
        """Helper to run pip commands within the virtual environment."""
        # Construct the full command by combining self.pip_cmd (python -m pip) with cmd_args
        full_cmd = self.pip_cmd + cmd_args 
        if verbose: print(f"PipPlugin: Running command: {' '.join(full_cmd)}")
        
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                full_cmd, # This is now a flat list of strings
                capture_output=True,
                text=True,
                check=True,
                cwd=self.project_root,
                timeout=self.policy.get("plugin_timeout_seconds", 300)
            )
            return result
        except subprocess.CalledProcessError as e:
            # e.cmd should now be a flat list, so ' '.join(e.cmd) will work correctly
            error_message = f"Pip command '{' '.join(e.cmd)}' failed with exit code {e.returncode}. Stderr: {e.stderr.strip()}"
            self.metrics["plugin_errors_total"] += 1
            AUDIT_LOGGER.error(f"Pip command failed: {error_message}")
            raise PluginOperationError(error_message) from e
        except FileNotFoundError:
            error_message = f"Python executable '{self.pip_cmd[0]}' not found in venv. Corrupted venv?"
            self.metrics["plugin_errors_total"] += 1
            AUDIT_LOGGER.critical(f"Pip command not found: {error_message}")
            raise PluginOperationError(error_message)
        except subprocess.TimeoutExpired as e:
            # e.cmd should now be a flat list, so ' '.join(e.cmd) will work correctly
            cmd_str_for_msg = ' '.join(e.cmd)
            error_message = f"Pip command '{cmd_str_for_msg}' timed out after {e.timeout} seconds."
            self.metrics["plugin_errors_total"] += 1
            AUDIT_LOGGER.error(f"Pip command timed out: {error_message}")
            raise PluginOperationError(error_message) from e
        except Exception as e:
            error_message = f"An unexpected error occurred while running pip command: {e}"
            self.metrics["plugin_errors_total"] += 1
            AUDIT_LOGGER.error(f"Unexpected pip error: {error_message}", exc_info=True)
            raise PluginOperationError(error_message) from e

    # --- Public API Methods (Implementations of EcosystemPlugin abstract methods) ---

    async def _install_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool:
        self._validate_package_name(package_name)
        self._check_policy("install", package_name, version_constraint)
        
        spec = f"{package_name}{version_constraint}" if version_constraint else package_name
        cmd_args = ["install", spec]
        await self._run_pip_cmd(cmd_args, verbose)
        self.metrics["install_success_total"] += 1
        return True

    async def _uninstall_impl(self, package_name: str, verbose: bool = False) -> bool:
        self._validate_package_name(package_name)
        self._check_policy("uninstall", package_name)
        cmd_args = ["uninstall", "-y", package_name]
        await self._run_pip_cmd(cmd_args, verbose)
        self.metrics["uninstall_success_total"] += 1
        return True

    async def _upgrade_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool:
        self._validate_package_name(package_name)
        self._check_policy("upgrade", package_name, version_constraint)
        
        spec = f"{package_name}{version_constraint}" if version_constraint else package_name
        cmd_args = ["install", "--upgrade", spec]
        await self._run_pip_cmd(cmd_args, verbose)
        self.metrics["upgrade_success_total"] += 1
        return True

    async def _list_installed_impl(self, verbose: bool = False) -> Dict[str, str]:
        cmd_args = ["freeze"]
        result = await self._run_pip_cmd(cmd_args, verbose)
        
        installed_packages = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if "==" in line:
                name, version = line.split("==", 1)
                installed_packages[name] = version
        return installed_packages

    async def _outdated_impl(self, verbose: bool = False) -> Dict[str, str]:
        if self.policy.get("offline"):
            raise PluginOperationError("Cannot check for outdated packages in offline mode.")
        
        cmd_args = ["list", "--outdated", "--format=json"]
        result = await self._run_pip_cmd(cmd_args, verbose)
        
        outdated_packages = {}
        try:
            data = json.loads(result.stdout)
            for pkg in data:
                outdated_packages[pkg["name"]] = pkg["latest_version"]
        except json.JSONDecodeError as e:
            raise PluginOperationError(f"Failed to parse pip outdated output: {e}")
        return outdated_packages

    async def _doctor_impl(self, verbose: bool = False) -> List[str]:
        cmd_args = ["check"]
        try:
            result = await self._run_pip_cmd(cmd_args, verbose)
            if "No broken requirements found." in result.stdout:
                return ["Pip: All dependencies are consistent."]
            return [f"Pip Check Issues: {result.stdout.strip()}"]
        except PluginOperationError as e:
            return [f"Pip Check Failed: {e}"]

    async def _fetch_features_impl(self, package_name: str, package_version: str) -> Dict[str, Any]:
        """Fetch package metadata from PyPI and vulnerability data from OSS Index."""
        if self.policy.get("offline"):
            raise PluginOperationError("Cannot fetch package metadata in offline mode.")

        headers = {'User-Agent': 'UPM-Pip-Plugin/1.1'}
        features = {
            'dependency_age_days': 500,
            'num_known_cves_past_year': 0,
            'maintainer_activity_score': 5.0,
            'transitive_dependency_count': 1,
            'has_install_scripts': 0,
            'license_is_permissive': 1
        }

        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(f"https://pypi.org/pypi/{package_name}/json") as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    
                    release_info = data.get('releases', {}).get(package_version)
                    if release_info:
                        upload_time_str = release_info[0].get('upload_time_iso_8601')
                        if upload_time_str:
                            upload_dt = datetime.fromisoformat(upload_time_str.replace('Z', '+00:00'))
                            features['dependency_age_days'] = (datetime.now(timezone.utc) - upload_dt).days
                    
                    if 'setup.py' in str(data) or 'pyproject.toml' in str(data):
                        features['has_install_scripts'] = 1
                    
                    license_name = data.get('info', {}).get('license', '').lower()
                    features['license_is_permissive'] = 1 if "mit" in license_name or "apache" in license_name else 0

            except aiohttp.ClientError as e:
                AUDIT_LOGGER.warning(f"Failed to fetch metadata for '{package_name}' from PyPI: {e}")
            except Exception as e:
                AUDIT_LOGGER.warning(f"Error parsing PyPI metadata for '{package_name}': {e}")
            
            try:
                purl = f"pkg:pypi/{package_name}@{package_version}"
                async with session.post("https://ossindex.sonatype.org/api/v3/component-report", json={"coordinates": [purl]}) as resp:
                    resp.raise_for_status()
                    vuln_data = (await resp.json())[0]
                    features['num_known_cves_past_year'] = len(vuln_data.get("vulnerabilities", []))
            except aiohttp.ClientError as e:
                AUDIT_LOGGER.warning(f"Failed to fetch vulnerability data for '{purl}' from OSS Index: {e}")
            except Exception as e:
                AUDIT_LOGGER.warning(f"Error parsing OSS Index vulnerability data for '{purl}': {e}")
        
        return features
        
    async def _search_impl(self, query: str, verbose: bool = False, filters: Optional[Dict[str, Any]] = None, sort_by: Optional[str] = None) -> List[Dict[str, str]]:
        if self.policy.get("offline"):
            raise PluginOperationError("Cannot search in offline mode.")
        
        AUDIT_LOGGER.warning("Pip search via CLI is deprecated. Using mock search results.")
        return [{"name": query, "version": "1.0.0", "description": f"Mock package for {query}"}]

    async def _export_native_manifest_impl(self, packages: Dict[str, str], verbose: bool = False) -> None:
        """Exports currently installed packages to a requirements.txt file."""
        requirements_path = os.path.join(self.project_root, "requirements.txt")
        try:
            with open(requirements_path, 'w', encoding="utf-8") as f:
                for name, version in packages.items():
                    f.write(f"{name}=={version}\n")
            if verbose: AUDIT_LOGGER.info(f"Successfully exported packages to {requirements_path}")
        except IOError as e:
            raise PluginOperationError(f"Failed to export to requirements.txt: {e}")

    async def _import_native_manifest_impl(self, verbose: bool = False) -> List[Dict[str, str]]:
        """Imports packages from a requirements.txt file."""
        requirements_path = os.path.join(self.project_root, "requirements.txt")
        if not os.path.exists(requirements_path):
            return []
        
        packages = []
        try:
            with open(requirements_path, 'r', encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = re.split(r'[<=>~!]+', line)
                        name = parts[0].strip()
                        version = line[len(name):].strip()
                        packages.append({"name": name, "version": version})
            if verbose: AUDIT_LOGGER.info(f"Successfully imported {len(packages)} packages from {requirements_path}")
            return packages
        except IOError as e:
            raise PluginOperationError(f"Failed to import from requirements.txt: {e}")

    async def _collect_metrics_impl(self, verbose: bool = False) -> Dict[str, Any]:
        metrics = self.metrics.copy()
        metrics["installed_packages_count"] = len(await self._list_installed_impl())
        if os.path.exists(self.venv_path):
            metrics["venv_size_mb"] = sum(os.path.getsize(os.path.join(dp, f)) for dp, dn, fn in os.walk(self.venv_path) for f in fn if os.path.exists(os.path.join(dp,f))) / (1024*1024)
        else:
            metrics["venv_size_mb"] = 0
        metrics["last_metric_collection_at"] = datetime.utcnow().isoformat() + "Z"
        return metrics

    async def _prune_impl(self, package_name: str, verbose: bool = False) -> bool:
        AUDIT_LOGGER.info(f"Pip: Pruning functionality for {package_name} (uninstall).")
        return await self._uninstall_impl(package_name, verbose)

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