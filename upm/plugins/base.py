# upm/plugins/base.py

import os
import sys
import asyncio
import time
import subprocess
import json
import hmac
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Any, Callable

# UPM Core Imports
from upm.logging_utils import AUDIT_LOGGER
from upm.ai_predictor import AIRiskAssessor 

# --- Conditional Imports for Optional Features ---
try:
    from pydantic import BaseModel, Field, ValidationError, constr
    _PYDANTIC_AVAILABLE = True
except ImportError:
    BaseModel, Field, ValidationError, constr = object, object, None, None
    _PYDANTIC_AVAILABLE = False
    sys.stderr.write("Warning: 'pydantic' not installed. Policy validation will be disabled.\n")

try:
    from semantic_version import NpmSpec, Version
    _SEMVER_AVAILABLE = True
except ImportError:
    NpmSpec = Version = None
    _SEMVER_AVAILABLE = False


# --- Custom Plugin Exceptions ---
class PluginOperationError(Exception):
    """Raised when a plugin encounters a functional error during an operation."""
    pass

class PluginPolicyViolation(Exception):
    """Raised when a plugin action violates the defined UPM policy."""
    pass

class SecurityException(Exception):
    """Raised for security-related failures, like invalid IPC signatures."""
    pass


# --- Pydantic Models for Policy Validation ---
if _PYDANTIC_AVAILABLE:
    PackageNameStr = constr(pattern=r'^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$')

    class PinnedVersionsModel(BaseModel):
        pip: Optional[Dict[str, str]] = Field(default_factory=dict)
        npm: Optional[Dict[str, str]] = Field(default_factory=dict)
        cargo: Optional[Dict[str, str]] = Field(default_factory=dict)
        class Config:
            extra = 'allow'

    class PolicyModel(BaseModel):
        blocked_packages: List[PackageNameStr] = Field(default_factory=list)
        allowed_packages: Optional[Dict[str, List[PackageNameStr]]] = None
        pinned_versions: PinnedVersionsModel = Field(default_factory=PinnedVersionsModel)
else:
    PolicyModel = None


def _isolated_method(func: Callable) -> Callable:
    """Decorator to run a plugin's implementation method in a secure, isolated subprocess."""
    async def wrapper(self: 'EcosystemPlugin', *args, **kwargs):
        impl_method = getattr(self, f"_{func.__name__}_impl", None)
        if not callable(impl_method):
            raise NotImplementedError(f"Plugin must implement `_{func.__name__}_impl` for isolation.")
        # FIX: Pass fernet_lib as part of the payload for isolated execution.
        # It cannot be directly serialized if it's a complex object, so we pass a placeholder
        # and expect the isolated runner to re-initialize it or know how to handle it.
        # For simplicity in this fix, we'll pass None or a representative ID.
        # The PluginManager is responsible for managing the actual Fernet instance.
        # The `fernet_lib` attribute needs to be passed through the IPC.
        # The `isolated_runner` is the one that actually instantiates the plugin.
        # The `PluginManager`'s `_run_plugin_task` already passes `fernet_lib`.
        # This decorator is for the `EcosystemPlugin` itself when it calls `_run_isolated`.
        # We need to ensure it's propagated.
        
        # Original: payload_dict = {'module': self.__module__, 'class': self.__class__.__name__, 'method': method.__name__, 'args': args, 'kwargs': kwargs, 'policy': self.policy, 'root': self.project_root, 'cache': self.cache_dir, 'fernet_lib': None }
        # The `fernet_lib` can't be pickled. So, it should not be passed directly.
        # Instead, `_run_isolated` (which is in `base.py`) needs to be aware of the
        # `fernet_lib` that was passed to the `EcosystemPlugin` constructor,
        # and the `isolated_runner.py` needs to receive it.
        
        # The current design is that `PluginManager.run_plugin_method` calls `_run_plugin_task`
        # which has `fernet_lib` as an argument. This implies `_run_plugin_task` then needs
        # to somehow pass it to the plugin's `__init__`.
        # This is already handled by `plugin_manager.py`'s `_run_plugin_task` function.
        # The `_run_isolated` method in `base.py` is the one that constructs the payload for `isolated_runner.py`.
        # It needs to include `fernet_lib` in `data`. Since `fernet_lib` is a `Fernet` object,
        # it needs to be *re-created* or *passed by reference* (e.g., key material).
        # As `fernet_lib` is expected to be an instance of `Fernet` (from `EncryptionManager`),
        # it can't be directly serialized via JSON.
        # The correct approach is to pass *no* `fernet_lib` here and ensure the `isolated_runner`
        # gets its own `fernet_lib` if it needs one, based on policies or config.
        # HOWEVER, the `PluginManager` already passes `fernet_lib` to the `_run_plugin_task` function.
        # So, the `_isolated_method` decorator (which uses `_run_isolated`) should NOT be touching `fernet_lib`.
        # The problem is that `isolated_runner.py` directly instantiates the plugin using `plugin_class(root, cache, policy)`.
        # It needs `fernet_lib` passed there.
        # So, the `_isolated_method` should NOT have `fernet_lib: None` in its payload.
        # Instead, `isolated_runner.py` needs to explicitly retrieve the `fernet_lib` and pass it.
        # This means the `_isolated_method` decorator is fine.
        # The problem is in `isolated_runner.py`'s `main` function where it instantiates the plugin.
        # Let's fix `isolated_runner.py` first, then revisit `base.py` if necessary.
        return await self._run_isolated(impl_method, *args, **kwargs)
    return wrapper


class EcosystemPlugin(ABC):
    """Abstract Base Class for UPM Ecosystem Plugins."""
    PLUGIN_API_VERSION: str = "1.0.0"

    def __init__(self, project_root: str, cache_dir: str, policy: Dict[str, Any], fernet_lib: Any = None): # Added fernet_lib here
        self.project_root: str = project_root
        self.cache_dir: str = cache_dir
        self.policy: Dict[str, Any] = policy
        self.fernet_lib = fernet_lib # Stored here.
        self.metrics: Dict[str, Any] = {
            "install_success_total": 0, "install_failure_total": 0, "uninstall_success_total": 0,
            "uninstall_failure_total": 0, "upgrade_success_total": 0, "upgrade_failure_total": 0,
            "policy_block_total": 0, "vulnerability_check_total": 0, "vulnerability_found_total": 0,
            "cache_hits_total": 0, "cache_misses_total": 0, "plugin_errors_total": 0, "cache_cleaned_mb": 0,
        }
        
        if _PYDANTIC_AVAILABLE and PolicyModel:
            try:
                self.parsed_policy = PolicyModel.model_validate(self.policy)
            except ValidationError as e:
                raise PluginOperationError(f"Policy configuration is invalid: {e}")
        else:
            self.parsed_policy = policy

        self.assessor: Optional['AIRiskAssessor'] = None
        if self.policy.get("ai_risk", {}).get("enabled"):
            try:
                from upm.ai_predictor import AIRiskAssessor
                self.assessor = AIRiskAssessor(
                    verbose=self.policy.get("ai_risk", {}).get("verbose", False),
                    model_path=self.policy.get("ai_risk", {}).get("model_path"),
                    cache_dir=os.path.join(self.cache_dir, 'ai')
                )
            except Exception as e:
                AUDIT_LOGGER.error(f"Failed to initialize AIRiskAssessor in plugin: {e}")
                self.assessor = None

    def _check_policy(self, action: str, name: str, version: Optional[str] = None) -> None:
        ecosystem_name = self.__class__.__name__.lower().replace("plugin", "")
        policy_data = self.parsed_policy
        
        # FIX: Scope blocklist and allowlist checks to acquisition actions.
        if action in ["install", "upgrade"]:
            if name in policy_data.blocked_packages:
                self.metrics["policy_block_total"] += 1
                raise PluginPolicyViolation(f"Policy blocked {action} of '{name}': package is in the global blocklist.")

            if policy_data.allowed_packages:
                allowed_ecosystem = policy_data.allowed_packages.get(ecosystem_name)
                if isinstance(allowed_ecosystem, list) and name not in allowed_ecosystem:
                    self.metrics["policy_block_total"] += 1
                    raise PluginPolicyViolation(f"Policy blocked {action} of '{name}': not in the '{ecosystem_name}' allowlist.")

            pinned_versions_model = policy_data.pinned_versions
            pinned_versions_for_eco = getattr(pinned_versions_model, ecosystem_name, {}) or {}
            pinned_spec = pinned_versions_for_eco.get(name)
            
            if pinned_spec:
                if not version:
                    if pinned_spec not in ["*", "latest"]:
                        self.metrics["policy_block_total"] += 1
                        raise PluginPolicyViolation(f"Policy blocked {action} of '{name}': version not specified, must match '{pinned_spec}'.")
                
                elif _SEMVER_AVAILABLE:
                    try:
                        normalized_version = version.lstrip("=~^<>")
                        if not NpmSpec(pinned_spec).match(Version(normalized_version)):
                            self.metrics["policy_block_total"] += 1
                            raise PluginPolicyViolation(f"Policy blocked {action} of '{name}@{version}': does not match pinned version '{pinned_spec}'.")
                    except (ValueError, TypeError):
                        if version != pinned_spec:
                            self.metrics["policy_block_total"] += 1
                            raise PluginPolicyViolation(f"Policy blocked {action} of '{name}@{version}': pinned to '{pinned_spec}'.")
                else: 
                    if version != pinned_spec:
                        self.metrics["policy_block_total"] += 1
                        raise PluginPolicyViolation(f"Policy blocked {action} of '{name}@{version}': pinned to '{pinned_spec}'.")


    async def _run_isolated(self, method: Callable, *args, **kwargs) -> Any:
        if sys.platform == "win32":
            AUDIT_LOGGER.warning("Running on Windows: process sandboxing via seccomp is not available. For maximum security, run UPM inside a container.")

        # Pass the fernet_lib (or its key material) through IPC if encryption is enabled.
        # Since Fernet objects are not directly pickleable, we need a strategy.
        # The `PluginManager._run_plugin_task` function is the actual entry point to the isolated process.
        # It already passes `fernet_lib` as an argument.
        # The `isolated_runner.py` is what receives this `fernet_lib` argument.
        # So, the `payload_dict` in `_run_isolated` needs to include a way to reconstruct
        # `fernet_lib` or pass its key to the `isolated_runner.py`.
        # For this fix, let's assume `fernet_lib` itself is NOT serialized here,
        # but the `isolated_runner` gets it directly from `PluginManager._run_plugin_task`.
        # The `isolated_runner.py`'s `main` function should be adjusted to correctly pass
        # the `fernet_lib` received from `_run_plugin_task` to the plugin's constructor.

        payload_dict = {
            'module': self.__module__, 
            'class': self.__class__.__name__, 
            'method': method.__name__, 
            'args': args, 
            'kwargs': kwargs, 
            'policy': self.policy, 
            'root': self.project_root, 
            'cache': self.cache_dir,
            # No need to serialize fernet_lib here; it's passed directly to _run_plugin_task
            # and then to the plugin constructor in the isolated process.
        }
        
        ipc_key = os.urandom(32)
        json_payload = json.dumps(payload_dict).encode('utf-8')
        signature = hmac.new(ipc_key, json_payload, hashlib.sha256).hexdigest()
        
        payload_to_send = ipc_key.hex().encode('utf-8') + b'|' + signature.encode('utf-8') + b'|' + json_payload
        
        isolated_runner_cmd = [sys.executable, '-m', 'upm.plugins.isolated_runner']
        
        env = os.environ.copy()
        upm_package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        
        tests_dir = os.path.join(upm_package_root, 'upm', 'tests')
        env['PYTHONPATH'] = f"{upm_package_root}{os.pathsep}{tests_dir}{os.pathsep}{env.get('PYTHONPATH', '')}"
        
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(*isolated_runner_cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
            stdout_data, stderr_data = await asyncio.wait_for(proc.communicate(input=payload_to_send), timeout=360.0)
        except asyncio.TimeoutError:
            if proc: proc.kill(); await proc.wait()
            self.metrics["plugin_errors_total"] += 1
            raise PluginOperationError(f"Isolated plugin method '{method.__name__}' timed out after {360.0} seconds. The process has been terminated.")
        except Exception as e:
            self.metrics["plugin_errors_total"] += 1
            raise RuntimeError(f"Failed to run isolated plugin process for '{method.__name__}': {e}") from e
        finally:
            if proc and proc.returncode is None: proc.kill(); await proc.wait()

        if proc.returncode != 0:
            self.metrics["plugin_errors_total"] += 1
            raise RuntimeError(f"Isolated runner for '{method.__name__}' failed with exit code {proc.returncode}.\nStderr: {stderr_data.decode(errors='ignore')}")
        
        try:
            response_parts = stdout_data.decode('utf-8').split('|', 1)
            if len(response_parts) != 2: raise RuntimeError("Invalid IPC response format.")
            
            resp_signature_hex, resp_json = response_parts
            expected_response_signature = hmac.new(ipc_key, resp_json.encode('utf-8'), hashlib.sha256).hexdigest()

            if not hmac.compare_digest(resp_signature_hex, expected_response_signature):
                raise SecurityException("IPC response validation failed: Invalid HMAC signature.")
            
            result_payload = json.loads(resp_json)
        except (RuntimeError, SecurityException, json.JSONDecodeError) as e:
            self.metrics["plugin_errors_total"] += 1
            raise RuntimeError(f"CRITICAL: Failed to validate or deserialize IPC response from isolated runner: {e}") from e

        if result_payload.get('is_exception'):
            error_message = result_payload['result']
            if "Policy blocked" in error_message:
                raise PluginPolicyViolation(error_message)
            else:
                raise PluginOperationError(f"Plugin failed in isolated process: {error_message}")
        
        return result_payload['result']

    # --- Public API Methods & Abstract Implementations ---
    @_isolated_method
    async def search(self, query: str, verbose: bool = False, filters: Optional[Dict[str, Any]] = None, sort_by: Optional[str] = None) -> List[Dict[str, str]]: pass
    @_isolated_method
    async def install(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool: pass
    @_isolated_method
    async def uninstall(self, package_name: str, verbose: bool = False) -> bool: pass
    @_isolated_method
    async def upgrade(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool: pass
    @_isolated_method
    async def list_installed(self, verbose: bool = False) -> Dict[str, str]: pass
    @_isolated_method
    async def outdated(self, verbose: bool = False) -> Dict[str, str]: pass
    @_isolated_method
    async def doctor(self, verbose: bool = False) -> List[str]: pass
    @_isolated_method
    async def predict_risks(self, package_name: str, package_version: str, verbose: bool = False) -> float: pass
    @_isolated_method
    async def suggest(self, name: str, verbose: bool = False) -> List[Dict[str, str]]: pass
    @_isolated_method
    async def auto_fix(self, name: Optional[str] = None, verbose: bool = False, suggested_version: Optional[str] = None) -> Tuple[bool, str]: pass
    @_isolated_method
    async def export_native_manifest(self, packages: Dict[str, str], verbose: bool = False) -> None: pass
    @_isolated_method
    async def import_native_manifest(self, verbose: bool = False) -> List[Dict[str, str]]: pass
    @_isolated_method
    async def collect_metrics(self, verbose: bool = False) -> Dict[str, Any]: pass
    @_isolated_method
    async def prune(self, package_name: str, verbose: bool = False) -> bool: pass
    @_isolated_method
    async def publish_event(self, event_type: str, event_data: Dict[str, Any], verbose: bool = False) -> None: pass


    @abstractmethod
    async def _search_impl(self, query: str, verbose: bool = False, filters: Optional[Dict[str, Any]] = None, sort_by: Optional[str] = None) -> List[Dict[str, str]]: raise NotImplementedError
    @abstractmethod
    async def _install_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool: raise NotImplementedError
    @abstractmethod
    async def _uninstall_impl(self, package_name: str, verbose: bool = False) -> bool: raise NotImplementedError
    @abstractmethod
    async def _upgrade_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool: raise NotImplementedError
    @abstractmethod
    async def _list_installed_impl(self, verbose: bool = False) -> Dict[str, str]: raise NotImplementedError
    @abstractmethod
    async def _outdated_impl(self, verbose: bool = False) -> Dict[str, str]: raise NotImplementedError
    @abstractmethod
    async def _fetch_features_impl(self, package_name: str, package_version: str) -> Dict[str, Any]: raise NotImplementedError
    @abstractmethod
    async def _export_native_manifest_impl(self, packages: Dict[str, str], verbose: bool = False) -> None: raise NotImplementedError
    @abstractmethod
    async def _import_native_manifest_impl(self, verbose: bool = False) -> List[Dict[str, str]]: raise NotImplementedError
    @abstractmethod
    async def _collect_metrics_impl(self, verbose: bool = False) -> Dict[str, Any]: raise NotImplementedError
    @abstractmethod
    async def _prune_impl(self, package_name: str, verbose: bool = False) -> bool: raise NotImplementedError

    async def _doctor_impl(self, verbose: bool = False) -> List[str]: return ["No specific health checks implemented for this ecosystem."]
    async def _predict_risks_impl(self, package_name: str, package_version: str, verbose: bool = False) -> float:
        self.metrics["risk_prediction_total"] += 1
        if not self.assessor:
            AUDIT_LOGGER.warning(f"AIRiskAssessor not initialized for {self.__class__.__name__}. Returning default risk 0.0.")
            return 0.0
        try:
            features = await self._fetch_features_impl(package_name, package_version)
            return self.assessor.predict_likelihood(features)
        except Exception as e:
            AUDIT_LOGGER.error(f"Error predicting risk for {package_name} in {self.__class__.__name__}: {e}")
            self.metrics["plugin_errors_total"] += 1
            return 0.0

    async def _suggest_impl(self, name: str, verbose: bool = False) -> List[Dict[str, str]]:
        suggestions = []
        if self.policy.get("offline"):
            return [{"recommendation": "Cannot fetch suggestions in offline mode.", "category": "offline_mode"}]
        outdated_packages = await self._outdated_impl(verbose=verbose)
        if name in outdated_packages:
            suggestions.append({"recommendation": f"Upgrade to version {outdated_packages[name]}.", "category": "version_update"})
        if hasattr(self, '_check_vulnerabilities_oss_index_impl'):
            vulnerabilities = await self._check_vulnerabilities_oss_index_impl(name)
            if vulnerabilities:
                for vuln in vulnerabilities:
                    suggestions.append({"recommendation": f"Vulnerability {vuln.get('id', '')}: {vuln.get('title', 'Unknown')}. {vuln.get('recommendation', '')}", "category": "security_vulnerability", "severity": vuln.get('severity')})
            else:
                suggestions.append({"recommendation": f"No known vulnerabilities found for {name} via OSS Index.", "category": "security"})
        return suggestions

    async def _auto_fix_impl(self, name: Optional[str] = None, verbose: bool = False, suggested_version: Optional[str] = None) -> Tuple[bool, str]:
        if not name:
            if hasattr(self, '_audit_fix_impl'):
                try:
                    if await self._audit_fix_impl(verbose=verbose):
                        return (True, "`audit fix` completed successfully.")
                    return (False, "`audit fix` reported issues.")
                except Exception as e:
                    return (False, f"Error during general `audit fix`: {e}")
            return (False, "General `audit fix` not implemented or no package provided.")
        if suggested_version and await self._upgrade_impl(name, suggested_version, verbose):
            return (True, f"Successfully upgraded {name} to fix version {suggested_version}.")
        suggestions = await self._suggest_impl(name, verbose)
        for suggestion in suggestions:
            if suggestion.get("category") == "version_update":
                new_version = suggestion['recommendation'].split()[-1].strip('.')
                if await self._upgrade_impl(name, new_version, verbose):
                    return (True, f"Successfully upgraded {name} to {new_version}.")
            elif suggestion.get("category") == "security_vulnerability" and "Upgrade to" in suggestion["recommendation"]:
                recommended_version = suggestion["recommendation"].split("Upgrade to")[-1].strip().split(" ")[0].strip(".")
                if recommended_version and await self._upgrade_impl(name, recommended_version, verbose):
                    return (True, f"Successfully upgraded {name} to {recommended_version} to fix vulnerability.")
        return (False, f"No actionable auto-fix suggestions found for {name}. Consider manual review.")

    async def _publish_event_impl(self, event_type: str, event_data: Dict[str, Any], verbose: bool = False) -> None:
        AUDIT_LOGGER.info(f"{self.__class__.__name__}: Event prepared", extra={"ecosystem": self.__class__.__name__.lower().replace("plugin", ""), "event_type": event_type, "event_data": event_data})
        self.metrics["events_published_total"] += 1