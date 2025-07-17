# upm/plugins/npm.py

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

# Import from other modules
from upm.plugins.base import EcosystemPlugin, PluginOperationError, PluginPolicyViolation
from upm.logging_utils import AUDIT_LOGGER

# --- Constants for Security ---
SAFE_NPM_PACKAGE_NAME_REGEX = re.compile(r"^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$")
DANGEROUS_NPM_ENV_VARS = ["NPM_CONFIG_PREFIX", "NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG"]
SHELL_INJECTION_CHARS_REGEX = re.compile(r'[;&|`$()]')


class NpmPlugin(EcosystemPlugin):
    """
    UPM Ecosystem Plugin for managing Node.js packages via npm.
    This plugin provides full support for installing, searching, auditing, and managing
    Node.js packages within the UPM framework.
    """

    PLUGIN_API_VERSION: str = "1.0.0"

    def __init__(self, project_root: str, cache_dir: str, policy: Dict[str, Any], fernet_lib: Any = None): # FIX: Add fernet_lib
        super().__init__(project_root, cache_dir, policy, fernet_lib=fernet_lib) # FIX: Pass fernet_lib to super
        self.npm_cache_dir: str = os.path.join(self.cache_dir, "npm")
        os.makedirs(self.npm_cache_dir, exist_ok=True)
        self.metrics["npm_binary_calls_total"] = 0
        
        self.npm_cmd_path = shutil.which("npm")
        if not self.npm_cmd_path:
             raise PluginOperationError("'npm' command not found. Ensure Node.js and npm are installed and in your PATH.")
        
        try:
            subprocess.run([self.npm_cmd_path, "--version"], capture_output=True, text=True, check=True, timeout=5)
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise PluginOperationError(f"npm command is not functional: {e}")

    def _validate_package_name(self, name: str):
        """Raises PluginOperationError if the package name is invalid."""
        if not SAFE_NPM_PACKAGE_NAME_REGEX.match(name):
            raise PluginOperationError(f"Invalid npm package name '{name}'.")

    async def _run_npm_cmd(self, cmd: List[str], verbose: bool = False, **kwargs: Any) -> subprocess.CompletedProcess:
        """Internal helper to run npm commands with security and usability considerations."""
        if kwargs.get('dry_run'):
            print(f"[Dry Run] Would execute: {self.npm_cmd_path} {' '.join(cmd)}")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='Dry run successful', stderr='')

        if not self.npm_cmd_path:
             raise PluginOperationError("'npm' command path not found during execution.")
        
        for arg in cmd:
            if SHELL_INJECTION_CHARS_REGEX.search(arg):
                self.metrics["plugin_errors_total"] += 1
                raise PluginOperationError(f"Potential shell injection detected in argument: '{arg}'")
        
        full_cmd: List[str] = [self.npm_cmd_path] + cmd
        self.metrics["npm_binary_calls_total"] += 1

        sanitized_env = os.environ.copy()
        for var in DANGEROUS_NPM_ENV_VARS:
            sanitized_env.pop(var, None)
        
        if self.policy.get("disallow_install_scripts", False) and cmd[0] in ["install", "ci", "update"]:
            full_cmd.append("--ignore-scripts")
        
        try:
            if verbose: print(f"NpmPlugin: Running command: {' '.join(full_cmd)}")
            result = await asyncio.to_thread(
                subprocess.run,
                full_cmd, capture_output=True, text=True, check=kwargs.get('check', True),
                cwd=self.project_root, shell=False, env=sanitized_env
            )
            return result
        except subprocess.CalledProcessError as e:
            self.metrics["plugin_errors_total"] += 1
            raise PluginOperationError(f"npm command '{' '.join(e.cmd)}' failed with exit code {e.returncode}. Stderr: {e.stderr.strip()}")
        except FileNotFoundError:
            self.metrics["plugin_errors_total"] += 1
            raise PluginOperationError(f"'{self.npm_cmd_path}' not found. Is Node.js installed?")
        except subprocess.TimeoutExpired as e:
            self.metrics["plugin_errors_total"] += 1
            raise PluginOperationError(f"npm command '{' '.join(e.cmd)}' timed out.")

    async def _install_impl(self, name: str, version_constraint: Optional[str] = None, verbose: bool = False, **kwargs) -> bool:
        self._validate_package_name(name)
        self._check_policy("install", name, version_constraint)
        
        package_spec = f"{name}@{version_constraint}" if version_constraint else name
        cmd = ["install", package_spec, f"--cache={self.npm_cache_dir}"]
        await self._run_npm_cmd(cmd, verbose, **kwargs)
        if not kwargs.get('dry_run'): self.metrics["install_success_total"] += 1
        return True

    async def _uninstall_impl(self, name: str, verbose: bool = False, **kwargs) -> bool:
        self._validate_package_name(name)
        self._check_policy("uninstall", name)
        cmd = ["uninstall", name]
        await self._run_npm_cmd(cmd, verbose, **kwargs)
        if not kwargs.get('dry_run'): self.metrics["uninstall_success_total"] += 1
        return True

    async def _upgrade_impl(self, name: str, version_constraint: Optional[str] = None, verbose: bool = False, **kwargs) -> bool:
        self._validate_package_name(name)
        self._check_policy("upgrade", name, version_constraint)
        version_to_install = version_constraint or self.policy.get("pinned_versions", {}).get("npm", {}).get(name, 'latest')
        package_spec = f"{name}@{version_to_install}"
        cmd = ["install", package_spec, f"--cache={self.npm_cache_dir}"]
        await self._run_npm_cmd(cmd, verbose, **kwargs)
        if not kwargs.get('dry_run'): self.metrics["upgrade_success_total"] += 1
        return True

    async def _list_installed_impl(self, verbose: bool = False) -> Dict[str, str]:
        cmd = ["list", "--json", "--depth=0"]
        result = await self._run_npm_cmd(cmd, verbose, check=False)
        if not result.stdout.strip(): return {}
        try:
            data = json.loads(result.stdout)
            return {name: details.get("version", "N/A") for name, details in data.get("dependencies", {}).items()}
        except json.JSONDecodeError:
            raise PluginOperationError("Failed to list npm packages: Could not parse JSON from npm.")

    async def _doctor_impl(self, verbose: bool = False, **kwargs) -> List[str]:
        if verbose and kwargs.get('dry_run'):
            print("[Dry Run] Would perform doctor checks on npm project.")
            return ["Doctor check skipped due to dry-run."]
        
        warnings = []
        if not os.path.exists(os.path.join(self.project_root, "package.json")):
            warnings.append("NPM: `package.json` not found in project root.")
        
        # Check for node_modules presence
        if not os.path.exists(os.path.join(self.project_root, "node_modules")):
            warnings.append("NPM: `node_modules` directory not found. Dependencies might not be installed. Run `npm install`.")

        try:
            audit_result = await self._run_npm_cmd(["audit", "--json"], verbose, check=False, **kwargs)
            self.metrics["vulnerability_check_total"] += 1
            data = json.loads(audit_result.stdout)
            
            # npm audit --json output structure can vary. Look for advisory info.
            vulnerabilities_found_count = 0
            if data.get("vulnerabilities"): # New npm audit format
                for pkg_name, pkg_vulns in data["vulnerabilities"].items():
                    for via_entry in pkg_vulns.get("via", []):
                        if isinstance(via_entry, dict) and "title" in via_entry:
                            warnings.append(f"NPM Audit: {pkg_name}: {via_entry['title']} (Severity: {via_entry.get('severity', 'unknown')})")
                            vulnerabilities_found_count += 1
            elif data.get("advisories"): # Old npm audit format
                for advisory_id, advisory_info in data["advisories"].items():
                    warnings.append(f"NPM Audit: {advisory_info.get('module_name', 'unknown')}: {advisory_info.get('title', 'Unknown vulnerability')} (Severity: {advisory_info.get('severity', 'unknown')})")
                    vulnerabilities_found_count += 1

            if vulnerabilities_found_count > 0:
                self.metrics["vulnerability_found_total"] += vulnerabilities_found_count
            else:
                warnings.append("NPM: `npm audit` found no vulnerabilities.")

        except (PluginOperationError, json.JSONDecodeError) as e:
            warnings.append(f"NPM: Could not run `npm audit`: {e}")
        return warnings

    async def _search_impl(self, query: str, verbose: bool = False, **kwargs) -> List[Dict[str, str]]:
        if verbose and kwargs.get('dry_run'):
            print(f"[Dry Run] Would search for npm package '{query}'.")
            return [{"name": "mock-npm-package", "version": "1.0.0", "description": "A mock package."}]
        if self.policy.get("offline"): raise PluginOperationError("Cannot search in offline mode.")
        self._validate_package_name(query)
        cmd = ["search", query, "--json"]
        result = await self._run_npm_cmd(cmd, verbose, **kwargs)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            raise PluginOperationError("Failed to parse search results from npm.")

    async def _outdated_impl(self, verbose: bool = False, **kwargs) -> Dict[str, str]:
        if verbose and kwargs.get('dry_run'):
            print("[Dry Run] Would check for outdated npm packages.")
            return {"mock-outdated-npm-package": "2.0.0"}
        if self.policy.get("offline"): raise PluginOperationError("Cannot check for outdated packages in offline mode.")
        cmd = ["outdated", "--json", "--long=false"] # Add --long=false for simpler output
        result = await self._run_npm_cmd(cmd, verbose, check=False)
        if not result.stdout.strip(): return {}
        try:
            data = json.loads(result.stdout)
            return {name: details.get("latest", "N/A") for name, details in data.items()}
        except json.JSONDecodeError:
            raise PluginOperationError("Failed to check outdated npm packages.")

    async def _fetch_features_impl(self, package_name: str, package_version: str) -> Dict[str, Any]:
        """Fetches package metadata from NPM registry and vulnerability data from OSS Index."""
        if self.policy.get("offline"): raise PluginOperationError("Cannot fetch package metadata in offline mode.")
        
        headers = {'User-Agent': 'UPM-Npm-Plugin/1.1'}
        features = {'dependency_age_days': 500, 'num_known_cves_past_year': 0, 'has_install_scripts': 0}

        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(f"https://registry.npmjs.org/{package_name}") as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    created_str = data.get('time', {}).get('created')
                    if created_str:
                        created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                        features['dependency_age_days'] = (datetime.now(timezone.utc) - created_dt).days
                    if any('install' in s or 'postinstall' in s for s in data.get('scripts', {}).keys()):
                         features['has_install_scripts'] = 1
            except aiohttp.ClientError as e:
                AUDIT_LOGGER.warning(f"Failed to fetch metadata for '{package_name}' from NPM Registry: {e}")
            except Exception as e:
                 AUDIT_LOGGER.warning(f"Error parsing NPM registry metadata for '{package_name}': {e}")
            try:
                purl = f"pkg:npm/{package_name}@{package_version}"
                async with session.post("https://ossindex.sonatype.org/api/v3/component-report", json={"coordinates": [purl]}) as resp:
                    resp.raise_for_status()
                    vuln_data = (await resp.json())[0]
                    features['num_known_cves_past_year'] = len(vuln_data.get("vulnerabilities", []))
            except aiohttp.ClientError as e:
                AUDIT_LOGGER.warning(f"Failed to fetch vulnerability data for '{purl}' from OSS Index: {e}")
            except Exception as e:
                 AUDIT_LOGGER.warning(f"Error parsing OSS Index vulnerability data for '{purl}': {e}")
        
        return features

    # FIX: Implement _check_vulnerabilities_oss_index_impl
    async def _check_vulnerabilities_oss_index_impl(self, package_name: str, package_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Checks for vulnerabilities using OSS Index. This method exists to directly
        satisfy the test's expectation, leveraging _fetch_features_impl's underlying call.
        """
        if self.policy.get("offline"):
            raise PluginOperationError("Cannot check vulnerabilities in offline mode.")

        # Use a dummy version if not provided for OSS Index PURL, or try to get from package.json/lockfile if available
        version_to_fetch = package_version if package_version else "latest"

        headers = {'User-Agent': 'UPM-Npm-Plugin/1.1'}
        vulnerabilities = []
        try:
            purl = f"pkg:npm/{package_name}@{version_to_fetch}"
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.post("https://ossindex.sonatype.org/api/v3/component-report", json={"coordinates": [purl]}) as resp:
                    resp.raise_for_status()
                    vuln_data = (await resp.json())[0]
                    
                    self.metrics["vulnerability_check_total"] += 1
                    if vuln_data.get("vulnerabilities"):
                        for vuln in vuln_data["vulnerabilities"]:
                            vulnerabilities.append({
                                "id": vuln.get("id"),
                                "title": vuln.get("title"),
                                "description": vuln.get("description"),
                                "severity": vuln.get("severity"),
                                "recommendation": vuln.get("recommendation"),
                                "url": vuln.get("references", [{}])[0].get("url")
                            })
                        self.metrics["vulnerability_found_total"] += len(vulnerabilities)
        except aiohttp.ClientError as e:
            AUDIT_LOGGER.warning(f"Failed to fetch vulnerability data for '{purl}' from OSS Index: {e}")
        except Exception as e:
            AUDIT_LOGGER.warning(f"Error parsing OSS Index vulnerability data for '{purl}': {e}")
        return vulnerabilities

    # FIX: Implement _manage_cache_impl
    async def _manage_cache_impl(self, verbose: bool = False) -> None:
        """Manages the npm cache, cleaning up old files based on size and TTL."""
        max_size_mb = self.policy.get("cache_policy", {}).get("max_size_mb", 100) # Default 100MB
        cache_ttl_days = self.policy.get("cache_policy", {}).get("cache_ttl_days", 30) # Default 30 days

        cache_path = self.npm_cache_dir
        if not os.path.exists(cache_path):
            AUDIT_LOGGER.info(f"NPM cache directory does not exist: {cache_path}")
            return

        AUDIT_LOGGER.info(f"NPM: Managing cache at {cache_path}. Max size: {max_size_mb}MB, TTL: {cache_ttl_days} days.")

        total_size_bytes = 0
        files_to_prune: List[Tuple[str, float]] = [] # (file_path, access_time)

        for dirpath, _, filenames in os.walk(cache_path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                try:
                    stats = os.stat(file_path)
                    total_size_bytes += stats.st_size
                    files_to_prune.append((file_path, stats.st_atime)) # access time
                except OSError as e:
                    AUDIT_LOGGER.warning(f"NPM cache management: Could not stat file {file_path}: {e}")

        # Sort oldest first by access time
        files_to_prune.sort(key=lambda x: x[1])

        # Prune by TTL first
        cutoff_time = time.time() - (cache_ttl_days * 86400) # seconds in a day
        cleaned_bytes_ttl = 0
        for file_path, access_time in files_to_prune[:]: # Iterate on a copy
            if access_time < cutoff_time:
                try:
                    size_of_file = os.path.getsize(file_path)
                    os.remove(file_path)
                    cleaned_bytes_ttl += size_of_file
                    total_size_bytes -= size_of_file
                    files_to_prune.remove((file_path, access_time)) # Remove from list to avoid double counting
                    AUDIT_LOGGER.debug(f"NPM cache: Pruned stale file {file_path} (TTL).")
                except OSError as e:
                    AUDIT_LOGGER.warning(f"NPM cache management: Could not remove stale file {file_path}: {e}")
        self.metrics["cache_cleaned_mb"] += cleaned_bytes_ttl / (1024 * 1024)

        # Prune by size if still over limit
        target_size_bytes = max_size_mb * 1024 * 1024
        cleaned_bytes_size = 0
        while total_size_bytes > target_size_bytes and files_to_prune:
            file_path, _ = files_to_prune.pop(0) # Remove oldest remaining file
            try:
                size_of_file = os.path.getsize(file_path)
                os.remove(file_path)
                cleaned_bytes_size += size_of_file
                total_size_bytes -= size_of_file
                AUDIT_LOGGER.debug(f"NPM cache: Pruned file {file_path} (size limit).")
            except OSError as e:
                AUDIT_LOGGER.warning(f"NPM cache management: Could not remove file {file_path}: {e}")
        self.metrics["cache_cleaned_mb"] += cleaned_bytes_size / (1024 * 1024)

        AUDIT_LOGGER.info(f"NPM cache management complete. Cleaned {(cleaned_bytes_ttl + cleaned_bytes_size) / (1024*1024):.2f} MB.")


    async def _export_native_manifest_impl(self, packages: Dict[str, str], verbose: bool = False) -> None:
        """Safely adds dependencies to package.json."""
        path = os.path.join(self.project_root, "package.json")
        try:
            if os.path.exists(path):
                with open(path, 'r', encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = {"name": "upm-project", "version": "1.0.0", "dependencies": {}}
            
            data.setdefault("dependencies", {}).update(packages)
            
            with open(path, 'w', encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            if verbose: AUDIT_LOGGER.info(f"Successfully exported packages to {path}")
        except (IOError, json.JSONDecodeError) as e:
            raise PluginOperationError(f"Failed to export to package.json: {e}")

    async def _import_native_manifest_impl(self, verbose: bool = False) -> List[Dict[str, str]]:
        """Reads dependencies from package.json."""
        path = os.path.join(self.project_root, "package.json")
        if not os.path.exists(path): return []
        try:
            with open(path, 'r', encoding="utf-8") as f: data = json.load(f)
            deps = []
            for dep_type in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
                deps.extend([{"name": name, "version": ver} for name, ver in data.get(dep_type, {}).items()])
            
            if verbose: AUDIT_LOGGER.info(f"Successfully imported {len(deps)} packages from {path}")
            return deps
        except (IOError, json.JSONDecodeError) as e:
            raise PluginOperationError(f"Failed to import from package.json: {e}")
            
    # --- Other Abstract Methods ---
    async def _auto_fix_impl(self, name: Optional[str] = None, verbose: bool = False, **kwargs) -> Tuple[bool, str]:
        if name:
            suggestions = await self._suggest_impl(name, verbose=verbose)
            for suggestion in suggestions:
                if suggestion.get("category") == "security_vulnerability" and suggestion.get("recommendation"):
                    if "Upgrade to" in suggestion["recommendation"]:
                        suggested_version = suggestion["recommendation"].split("Upgrade to")[-1].strip().split(" ")[0]
                        if suggested_version:
                            await self._upgrade_impl(name, suggested_version, verbose=verbose, **kwargs)
                            return True, f"Attempted to upgrade {name} to fix version {suggested_version}."
            return False, f"No specific auto-fix found for {name}. Consider `npm audit fix`."
        
        if not os.path.exists(os.path.join(self.project_root, "package-lock.json")) and \
           not os.path.exists(os.path.join(self.project_root, "npm-shrinkwrap.json")):
           return False, "Cannot run `npm audit fix` without a `package-lock.json` or `npm-shrinkwrap.json`."

        result = await self._run_npm_cmd(["audit", "fix"], verbose, check=False, **kwargs)
        if result.returncode != 0 and "fixed" not in result.stdout.lower() and "fixed" not in result.stderr.lower():
            return False, f"`npm audit fix` failed or found unfixable issues. Stderr: {result.stderr.strip()}"
        return True, "`npm audit fix` completed successfully."

    async def _suggest_impl(self, name: str, verbose: bool = False) -> List[Dict[str, str]]:
        suggestions: List[Dict[str, str]] = []

        if self.policy.get("offline"):
            suggestions.append({"recommendation": "Cannot fetch suggestions in offline mode.", "category": "offline_mode"})
            return suggestions

        latest_version = None
        try:
            headers = {'User-Agent': 'UPM-Npm-Plugin/1.1'}
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(f"https://registry.npmjs.org/{name}") as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    latest_version = data.get('dist-tags', {}).get('latest')
                    if latest_version:
                        suggestions.append({"recommendation": f"Latest stable version is {latest_version}.", "category": "version_update"})
        except aiohttp.ClientError as e:
            AUDIT_LOGGER.warning(f"NPM: Could not fetch latest version for '{name}': {e}")
        except Exception as e:
            AUDIT_LOGGER.warning(f"NPM: Error parsing registry data for '{name}': {e}")

        if os.path.exists(os.path.join(self.project_root, "package.json")):
            try:
                audit_result = await self._run_npm_cmd(["audit", "--json"], verbose, check=False)
                audit_data = json.loads(audit_result.stdout)
                
                vulnerabilities_found = []
                if audit_data.get("vulnerabilities"):
                    for pkg_name, pkg_vulns in audit_data["vulnerabilities"].items():
                        if pkg_name != name: continue # Only show vulns for the requested package
                        for via_entry in pkg_vulns.get("via", []):
                            if isinstance(via_entry, dict) and "title" in via_entry:
                                recommendations = []
                                if pkg_vulns.get("fixAvailable") and isinstance(pkg_vulns["fixAvailable"], dict) and pkg_vulns["fixAvailable"].get("version"):
                                    recommendations.append(f"Upgrade to {pkg_vulns['fixAvailable']['version']}")
                                else:
                                    recommendations.append("Manual review required")

                                vulnerabilities_found.append({
                                    "id": via_entry.get("url", "").split('/')[-1],
                                    "title": via_entry["title"],
                                    "severity": via_entry.get("severity", "unknown"),
                                    "recommendation": ", ".join(recommendations)
                                })
                
                if vulnerabilities_found:
                    for vuln in vulnerabilities_found:
                        suggestions.append({
                            "recommendation": f"Vulnerability {vuln.get('id', 'N/A')}: {vuln.get('title', 'Unknown')}. {vuln.get('recommendation', '')}",
                            "category": "security_vulnerability",
                            "severity": vuln.get('severity')
                        })
                else:
                    suggestions.append({"recommendation": f"No known vulnerabilities found for {name} via `npm audit`.", "category": "security"})

            except (PluginOperationError, json.JSONDecodeError) as e:
                AUDIT_LOGGER.warning(f"NPM: Could not run `npm audit` for suggestions: {e}")
        else:
            suggestions.append({"recommendation": "`package.json` not found; cannot run `npm audit` for vulnerability suggestions.", "category": "info"})
        
        return suggestions

    async def _collect_metrics_impl(self, verbose: bool = False) -> Dict[str, Any]: 
        metrics = self.metrics.copy()
        try:
            installed_list = await self._list_installed_impl()
            metrics["installed_packages_count"] = len(installed_list)
        except PluginOperationError:
            metrics["installed_packages_count"] = 0 # Could not list packages

        try:
            metrics["npm_cache_size_mb"] = sum(os.path.getsize(os.path.join(dp, f)) for dp, dn, fn in os.walk(self.npm_cache_dir) for f in fn if os.path.exists(os.path.join(dp,f))) / (1024*1024)
        except FileNotFoundError:
             metrics["npm_cache_size_mb"] = 0 # Cache dir doesn't exist
        
        metrics["last_metric_collection_at"] = datetime.utcnow().isoformat() + "Z"
        return metrics

    async def _prune_impl(self, package_name: Optional[str] = None, verbose: bool = False, **kwargs) -> bool:
        if package_name:
            AUDIT_LOGGER.info(f"NPM: Pruning (uninstalling) {package_name} as it's unused.")
            return await self._uninstall_impl(package_name, verbose=verbose, **kwargs)
        
        AUDIT_LOGGER.info(f"NPM: Running general `npm prune` to remove extraneous packages.")
        result = await self._run_npm_cmd(["prune"], verbose, **kwargs)
        return result.returncode == 0
    
    async def _publish_event_impl(self, event_type: str, event_data: Dict[str, Any], verbose: bool = False) -> None:
        """Publishes an event to a webhook, if configured in policy."""
        webhook_url = self.policy.get("events", {}).get("webhook_url")
        if not webhook_url:
            if verbose: AUDIT_LOGGER.info("No webhook URL configured; skipping event publishing.")
            return
        
        payload = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "plugin": "npm",
            "project_root": self.project_root,
            "data": event_data
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, timeout=10) as response:
                    response.raise_for_status()
                    AUDIT_LOGGER.info(f"Successfully published event '{event_type}' to webhook.")
        except aiohttp.ClientError as e:
            AUDIT_LOGGER.error(f"Failed to publish event to webhook: {e}")
        except asyncio.TimeoutError:
            AUDIT_LOGGER.error("Failed to publish event to webhook: Request timed out.")


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