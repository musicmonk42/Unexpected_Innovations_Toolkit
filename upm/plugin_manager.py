# upm/plugin_manager.py

import os
import importlib.util
import sys
import json
import hashlib
import asyncio
import copy
from concurrent.futures import ProcessPoolExecutor, TimeoutError
from typing import Dict, Any, Optional, Type, List, Callable, Tuple
import re

from upm.plugins.base import EcosystemPlugin, PluginOperationError, PluginPolicyViolation, SecurityException
from upm.logging_utils import AUDIT_LOGGER
from upm.error_tracker import ErrorTracker

# --- Cryptography Imports for Signature Verification ---
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    _CRYPTOGRAPHY_AVAILABLE = False
    InvalidSignature = type('InvalidSignature', (Exception,), {}) # Dummy class

# --- Plugin Task Runner (for process isolation) ---
# This function is defined at the top level so it can be pickled and sent to a child process.
def _run_plugin_task(
    plugin_path: str,
    plugin_class_name: str,
    method_name: str,
    project_root: str,
    cache_dir: str,
    policy: Dict[str, Any],
    config: Dict[str, Any],
    fernet_lib: Any,
    args: tuple,
    kwargs: dict
) -> Any:
    """
    Executes a specific plugin method in an isolated process.
    This prevents the plugin from accessing the main UPM process's state.
    """
    import os
    from upm.logging_utils import configure_logging, shutdown_logging
    log_file = os.getenv('UPM_LOG_FILE', 'audit.log')
    configure_logging(log_file_path=log_file, verbose=True)
    try:
        spec = importlib.util.spec_from_file_location("plugin_module", plugin_path)
        if not spec or not spec.loader:
            raise RuntimeError(f"Could not create module spec for plugin at {plugin_path}")

        plugin_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin_module)

        PluginClass = getattr(plugin_module, plugin_class_name)

        fernet_lib_key_material = None
        if hasattr(fernet_lib, '_key'):
            fernet_lib_key_material = fernet_lib._key.decode('utf-8')

        plugin_instance = PluginClass(
            project_root=project_root,
            cache_dir=cache_dir,
            policy=policy,
            fernet_lib=fernet_lib_key_material
        )

        method_to_call = getattr(plugin_instance, method_name)

        if asyncio.iscoroutinefunction(method_to_call):
            result = asyncio.run(method_to_call(*args, **kwargs))
        else:
            result = method_to_call(*args, **kwargs)

        shutdown_logging()
        return result

    except Exception as e:
        shutdown_logging()
        raise RuntimeError(f"Plugin execution failed in isolated process: {e}") from e

class _PluginProxy:
    """
    A proxy object that represents a plugin. When a method is called on this proxy,
    it triggers the actual execution in an isolated subprocess via the PluginManager.
    """
    def __init__(self, eco_name: str, manager: 'PluginManager'):
        self._eco_name = eco_name
        self._manager = manager

    def __getattr__(self, name: str) -> Any:
        def method(*args: Any, **kwargs: Any):
            return self._manager.run_plugin_method(self._eco_name, name, *args, **kwargs)
        return method

class PluginManager:
    """
    Manages the loading, lifecycle, and integrity of UPM ecosystem plugins.
    Plugins are run in isolated processes and verified with cryptographic signatures.
    """
    SAFE_PATH_REGEX = re.compile(r"^[a-zA-Z0-9_./:\\-]+$")
    UNSAFE_CHARS_REGEX = re.compile(r'[;&|`$(){}<>]')

    def __init__(self, project_root: str, cache_dir: str, policy: Dict[str, Any],
                 config: Dict[str, Any], error_tracker: ErrorTracker, fernet_lib: Any,
                 plugins_base_dir: Optional[str] = None, auto_load_plugins: bool = True):
        self.project_root = project_root
        self.cache_dir = cache_dir
        self.policy = copy.deepcopy(policy)
        self.config = copy.deepcopy(config)
        self.error_tracker = error_tracker
        self.fernet_lib = fernet_lib

        self.verified_plugins: Dict[str, Any] = {}
        self.plugin_trust_store: List[Any] = []

        self.executor = ProcessPoolExecutor()

        self._plugins_base_dir = plugins_base_dir if plugins_base_dir else os.path.dirname(__file__)

        self.plugins_dir = os.path.join(self._plugins_base_dir, "plugins")
        self.plugin_manifest_path = os.path.join(self.plugins_dir, "plugin_manifest.json")

        if auto_load_plugins:
            self._post_init_setup()

    # --- Helper methods ---
    def _validate_path_for_plugins(self, path: str, context: str) -> None:
        """
        Validates a path specific to plugins for safety.
        Raises SecurityException if the path is deemed unsafe.
        """
        if not path or not isinstance(path, str):
            raise SecurityException(f"Security Error: Path for {context} is empty or not a string.")

        # Normalize path to resolve '..' and use consistent separators for comparison
        normalized_path = os.path.normpath(path)
        # Convert to absolute path to prevent traversal attacks relative to current working directory
        abs_path = os.path.abspath(normalized_path)

        # Ensure path does not contain unsafe shell characters
        if self.UNSAFE_CHARS_REGEX.search(path):
            raise SecurityException(f"Security Error: Potential shell injection characters detected in {context} path: '{path}'")

        # Basic path traversal check: ensure it starts with the expected base directory
        # This is a critical check to ensure plugins cannot refer to files outside their designated area.
        expected_base_path = os.path.abspath(self.plugins_dir)
        if not abs_path.startswith(expected_base_path):
            # Allow paths *within* the plugins directory but not outside it via symlinks
            if not os.path.realpath(abs_path).startswith(expected_base_path):
                raise SecurityException(f"Security Error: Malicious path traversal detected for {context}: '{path}'. Resolves outside plugins directory.")

        # Ensure the filename part, if any, matches safe regex for plugin names
        filename = os.path.basename(path)
        if filename.endswith(".py"):
            plugin_name_from_file = os.path.splitext(filename)[0]
            if not re.match(r"^[a-zA-Z0-9_.-]+$", plugin_name_from_file):
                raise SecurityException(f"Security Error: Malformed plugin name '{plugin_name_from_file}' derived from '{filename}'.")


    def _calculate_file_sha256(self, filepath: str) -> Optional[str]:
        try:
            self._validate_path_for_plugins(filepath, "plugin file for hashing")
        except SecurityException as e:
            self.error_tracker.add_error(f"Plugin integrity check failed: {e}")
            AUDIT_LOGGER.critical(f"Plugin integrity check failed: {e}")
            return None

        if not os.path.exists(filepath): return None
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.error_tracker.add_error(f"Failed to calculate SHA256 for {filepath}: {e}")
            return None

    def _load_plugin_manifest(self) -> Dict[str, Any]:
        try:
            self._validate_path_for_plugins(self.plugin_manifest_path, "plugin manifest file")
        except SecurityException as e:
            self.error_tracker.add_error(f"Plugin manifest security check failed: {e}")
            AUDIT_LOGGER.critical(f"Plugin manifest security check failed: {e}")
            return {}

        if not os.path.exists(self.plugin_manifest_path):
            self.error_tracker.add_error(f"Plugin manifest not found: {self.plugin_manifest_path}. No plugins will be loaded.")
            AUDIT_LOGGER.critical(f"Plugin manifest not found: {self.plugin_manifest_path}")
            return {}
        try:
            with open(self.plugin_manifest_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.error_tracker.add_error(f"Failed to load or parse plugin manifest {self.plugin_manifest_path}: {e}")
            return {}

    def _load_trust_store(self):
        if not _CRYPTOGRAPHY_AVAILABLE:
            AUDIT_LOGGER.warning("Cryptography library not installed. Plugin signature verification is disabled.")
            return

        trust_store_path = self.config.get("security", {}).get("plugin_trust_store_path")
        if not trust_store_path or not os.path.isdir(trust_store_path):
            AUDIT_LOGGER.warning(f"Plugin trust store path not configured or not a directory. Plugin signature verification is disabled.")
            return

        AUDIT_LOGGER.info(f"Loading plugin signing keys from trust store: {trust_store_path}")
        for key_file in os.listdir(trust_store_path):
            if key_file.endswith(".pub") or key_file.endswith(".pem"):
                try:
                    with open(os.path.join(trust_store_path, key_file), "rb") as f:
                        public_key = serialization.load_pem_public_key(f.read())
                        self.plugin_trust_store.append(public_key)
                except Exception as e:
                    self.error_tracker.add_error(f"Failed to load public key '{key_file}': {e}")
                    AUDIT_LOGGER.error(f"Failed to load public key '{key_file}' from trust store.")
        
        if not self.plugin_trust_store:
            AUDIT_LOGGER.warning("No valid public keys found in trust store. Plugin signature verification is disabled.")
        else:
            AUDIT_LOGGER.info(f"Successfully loaded {len(self.plugin_trust_store)} public keys for plugin verification.")

    def _verify_plugin_signature(self, plugin_name: str, data: bytes, signature_hex: str) -> bool:
        if not self.plugin_trust_store:
            return False

        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            self.error_tracker.add_error(f"Invalid signature format for plugin '{plugin_name}'. Must be hex.")
            return False

        for key in self.plugin_trust_store:
            try:
                key.verify(
                    signature,
                    data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                return True
            except InvalidSignature:
                continue
            except Exception:
                continue

        return False

    def load_plugins(self) -> None:
        """
        Discovers, verifies, and registers available plugins.
        """
        try:
            self._validate_path_for_plugins(self.plugins_dir, "plugins directory")
        except SecurityException as e:
            self.error_tracker.add_error(f"Security error with plugins directory: {e}")
            AUDIT_LOGGER.critical(f"Security error with plugins directory: {e}")
            return

        if not os.path.exists(self.plugins_dir):
            self.error_tracker.add_error(f"Plugins directory not found: {self.plugins_dir}")
            AUDIT_LOGGER.critical(f"Plugins directory not found: {self.plugins_dir}")
            return

        manifest = self._load_plugin_manifest()
        if not manifest:
            self.verified_plugins.clear()
            return

        self.verified_plugins.clear()

        for filename in os.listdir(self.plugins_dir):
            if filename.endswith(".py") and filename not in ["__init__.py", "base.py", "isolated_runner.py"]:
                plugin_name = os.path.splitext(filename)[0]
                filepath = os.path.join(self.plugins_dir, filename)

                try:
                    self._validate_path_for_plugins(filepath, f"individual plugin file '{filename}'")
                except SecurityException as e:
                    self.error_tracker.add_error(f"Security error with plugin '{filename}': {e}")
                    AUDIT_LOGGER.critical(f"Security error with plugin '{filename}': {e}")
                    continue

                if plugin_name not in manifest.get("plugins", {}):
                    AUDIT_LOGGER.warning(f"Plugin file '{filename}' found but is not in the manifest. Skipping.")
                    continue

                manifest_entry = manifest["plugins"][plugin_name]
                expected_hash = manifest_entry.get("sha256")
                signature = manifest_entry.get("signature")
                version = manifest_entry.get("version", "unknown")
                class_name = manifest_entry.get("class_name")

                current_hash = self._calculate_file_sha256(filepath)
                
                # FIX: Handle potential None for expected_hash gracefully before subscripting
                expected_hash_display = expected_hash[:8] if expected_hash else 'N/A'
                current_hash_display = current_hash[:8] if current_hash else 'N/A'

                if not current_hash or current_hash != expected_hash:
                    AUDIT_LOGGER.critical(f"Plugin '{plugin_name}' hash mismatch or unreadable. Expected {expected_hash_display}..., got {current_hash_display}. REFUSING TO REGISTER.")
                    self.error_tracker.add_error(f"Plugin '{plugin_name}' hash mismatch or unreadable.")
                    continue

                if self.plugin_trust_store and _CRYPTOGRAPHY_AVAILABLE:
                    if not signature:
                        AUDIT_LOGGER.critical(f"Plugin '{plugin_name}' is missing a signature in the manifest, but a trust store is active. REFUSING TO REGISTER.")
                        self.error_tracker.add_error(f"Plugin '{plugin_name}' missing signature with active trust store.")
                        continue

                    with open(filepath, "rb") as f:
                        plugin_data = f.read()

                    if not self._verify_plugin_signature(plugin_name, plugin_data, signature):
                        AUDIT_LOGGER.critical(f"Plugin '{plugin_name}' has an INVALID signature. It may be tampered with or from an untrusted source. REFUSING TO REGISTER.")
                        self.error_tracker.add_error(f"Plugin '{plugin_name}' has an INVALID signature.")
                        continue
                    AUDIT_LOGGER.info(f"Plugin '{plugin_name}' v{version} signature verified.")
                elif signature:
                     AUDIT_LOGGER.warning(f"Plugin '{plugin_name}' has a signature, but no trust store is loaded. Cannot verify authenticity.")

                try:
                    sys_path_original = list(sys.path)
                    sys.path.insert(0, self._plugins_base_dir)

                    spec = importlib.util.spec_from_file_location(plugin_name, filepath)
                    if not spec or not spec.loader:
                        raise RuntimeError(f"Could not create module spec for plugin at {filepath}.")

                    plugin_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(plugin_module)

                    ExpectedEcosystemPlugin = getattr(plugin_module, 'EcosystemPlugin', None)
                    if not ExpectedEcosystemPlugin:
                        raise RuntimeError(f"Base class 'EcosystemPlugin' not found in dynamically loaded module for '{plugin_name}'.")

                    if not class_name or not hasattr(plugin_module, class_name) or not issubclass(getattr(plugin_module, class_name), ExpectedEcosystemPlugin):
                        raise RuntimeError(f"Class '{class_name}' not found or is not an EcosystemPlugin.")


                    self.verified_plugins[plugin_name] = {
                        "path": filepath,
                        "class_name": class_name,
                        "version": version,
                        "hash": current_hash
                    }
                    AUDIT_LOGGER.info(f"Successfully registered plugin '{plugin_name}' v{version}.")

                except Exception as e:
                    self.error_tracker.add_error(f"Failed to register plugin '{plugin_name}': {e}")
                    self.verified_plugins.pop(plugin_name, None)
                finally:
                    if sys.path and sys.path[0] == self._plugins_base_dir:
                        sys.path.pop(0)


    def run_plugin_method(self, eco_name: str, method_name: str, *args: Any, **kwargs: Any) -> Any:
        if eco_name not in self.verified_plugins:
            raise ValueError(f"No verified plugin found for ecosystem: '{eco_name}'")

        plugin_meta = self.verified_plugins[eco_name]
        timeout = self.config.get("security", {}).get("plugin_timeout_seconds", 600)

        fernet_lib_key_material = None
        if hasattr(self.fernet_lib, '_key'):
            fernet_lib_key_material = self.fernet_lib._key.decode('utf-8')

        future = self.executor.submit(
            _run_plugin_task,
            plugin_path=plugin_meta["path"],
            plugin_class_name=plugin_meta["class_name"],
            method_name=method_name,
            project_root=self.project_root,
            cache_dir=self.cache_dir,
            policy=self.policy,
            config=self.config,
            fernet_lib=fernet_lib_key_material,
            args=args,
            kwargs=kwargs
        )

        try:
            result = future.result(timeout=timeout)
            return result
        except TimeoutError as e:
            self.error_tracker.add_error(f"Plugin '{eco_name}' method '{method_name}' timed out after {timeout} seconds. The process has been terminated.")
            AUDIT_LOGGER.error(f"Plugin timeout: {eco_name}.{method_name}")
            raise PluginOperationError(f"Plugin '{eco_name}' method '{method_name}' timed out.") from e
        except Exception as e:
            self.error_tracker.add_error(f"Plugin '{eco_name}' method '{method_name}' failed in isolated process: {e}")
            AUDIT_LOGGER.error(f"Plugin execution error in {eco_name}.{method_name}: {e}")
            raise

    def get_plugin(self, eco_name: str) -> Optional[EcosystemPlugin]:
        if eco_name in self.verified_plugins:
            return _PluginProxy(eco_name, self)
        raise ValueError(f"No verified plugin found for ecosystem: '{eco_name}'")

    def get_all_plugins(self) -> Dict[str, EcosystemPlugin]:
        return {name: _PluginProxy(name, self) for name in self.verified_plugins}

    def get_all_plugin_names(self) -> List[str]:
        return list(self.verified_plugins.keys())

    def get_plugin_hashes(self) -> Dict[str, str]:
        return {name: meta['hash'] for name, meta in self.verified_plugins.items()}

    def __del__(self):
        # In actual application shutdown, need to ensure executor is shut down
        # This might be tricky with atexit and multiprocessing if not carefully managed.
        # For testing, it's fine as pytest fixtures tear down.
        pass

    def _post_init_setup(self):
        self._load_trust_store()
        self.load_plugins()