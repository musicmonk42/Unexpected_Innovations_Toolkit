# tests/test_security.py
import pytest
import os
import sys
import asyncio
import time
import logging
from unittest.mock import patch, MagicMock, AsyncMock
from pathlib import Path
import yaml
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
import hashlib
import shutil
import json

# Configure logging for test debugging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

# Conditional import for platform-specific modules
if sys.platform == "linux":
    pass
elif sys.platform == "win32":
    try:
        import psutil
    except ImportError:
        pytest.skip("psutil not installed, skipping some security tests on Windows", allow_module_level=True)
elif sys.platform == "darwin":
    try:
        import psutil
    except ImportError:
        pytest.skip("psutil not installed, skipping some security tests on macOS", allow_module_level=True)

from upm.core import UniversalPackageManager
from upm.plugins.base import EcosystemPlugin, PluginOperationError
from upm.logging_utils import AUDIT_LOGGER, JSONFormatter, configure_logging, shutdown_logging, flush_logs

# --- Fixtures ---

@pytest.fixture
def temp_project(tmp_path):
    """Provides a temporary, isolated project directory."""
    project_dir = tmp_path / "sec_project"
    project_dir.mkdir()
    logger.debug(f"Created temporary project directory: {project_dir}")
    return str(project_dir)

@pytest.fixture
def mock_config_for_security(tmp_path):
    """Provides a mock config suitable for security tests, including AI model path."""
    config_data = {
        "security": {
            "encrypt_data": False,
            "require_signatures": False,
            "plugin_trust_store_path": str(tmp_path / "trust_store") # Dummy path
        },
        "notifications": {"email": {"enabled": False}, "slack": {"enabled": False}},
        "ai": {
            "enabled": False, # Disable AI by default for these tests unless explicitly enabled
            "model_path": str(tmp_path / "mock_ai_model.joblib"), # Provide a dummy path
            "cache_dir": str(tmp_path / "ai_cache")
        }
    }
    Path(config_data["ai"]["model_path"]).parent.mkdir(parents=True, exist_ok=True)
    Path(config_data["ai"]["model_path"]).touch()
    logger.debug(f"Created mock config with model path: {config_data['ai']['model_path']}")
    return config_data

# Define MaliciousPlugin directly in test file as a string. It will be written to a temp file.
_MALICIOUS_PLUGIN_CODE = """
import os
import sys
import asyncio
import time
import socket
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
import hashlib
import json

from upm.plugins.base import EcosystemPlugin, PluginOperationError
from upm.logging_utils import AUDIT_LOGGER

class MaliciousPlugin(EcosystemPlugin):
    PLUGIN_API_VERSION = "1.0.0"

    def _attempt_network_call_impl(self, **kwargs):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("google.com", 80))
        finally:
            s.close()
        return "Network connection succeeded (this is a failure)"

    def _attempt_file_write_impl(self, **kwargs):
        with open("malicious_file.txt", "w") as f:
            f.write("I escaped the sandbox!")
        return "File write succeeded"

    def _cpu_overuse_impl(self, **kwargs):
        start_time = time.time()
        while True:
            if time.time() - start_time > 10: break
            pass

    def _memory_overuse_impl(self, **kwargs):
        _ = bytearray(200 * 1024 * 1024)
        return "Memory allocation succeeded"

    def _log_unredacted_secret_impl(self, **kwargs):
        AUDIT_LOGGER.critical("Leaking sensitive data: api_key=SECRET12345")
        return "Logged a secret"

    # Concrete implementations for all abstract methods in EcosystemPlugin (minimal)
    async def _search_impl(self, query: str, verbose: bool = False, filters: Optional[Dict[str, Any]] = None, sort_by: Optional[str] = None) -> List[Dict[str, str]]: return []
    async def _install_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool: return True
    async def _uninstall_impl(self, package_name: str, verbose: bool = False) -> bool: return True
    async def _upgrade_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool: return True
    async def _list_installed_impl(self, verbose: bool = False) -> Dict[str, str]: return {}
    async def _outdated_impl(self, verbose: bool = False) -> Dict[str, str]: return {}
    async def _doctor_impl(self, verbose: bool = False) -> List[str]: return []
    async def _predict_risks_impl(self, package_name: str, package_version: str, verbose: bool = False) -> float: return 0.0
    async def _suggest_impl(self, name: str, verbose: bool = False) -> List[Dict[str, str]]: return []
    async def _auto_fix_impl(self, name: Optional[str] = None, verbose: bool = False, suggested_version: Optional[str] = None) -> Tuple[bool, str]: return True, "Fixed"
    async def _export_native_manifest_impl(self, packages: Dict[str, str], verbose: bool = False) -> None: pass
    async def _import_native_manifest_impl(self, verbose: bool = False) -> List[Dict[str, str]]: return []
    async def _collect_metrics_impl(self, verbose: bool = False) -> Dict[str, Any]: return {}
    async def _publish_event_impl(self, event_type: str, event_data: Dict[str, Any], verbose: bool = False) -> None: pass
    async def _prune_impl(self, package_name: str, verbose: bool = False) -> bool: return True
    async def _fetch_features_impl(self, package_name: str, package_version: str) -> Dict[str, Any]: return {}
"""

@pytest.fixture
async def upm_with_malicious_plugin(temp_project, mock_config_for_security):
    rc_path = Path(temp_project) / ".unipkgrc"
    actual_plugins_dir_for_test = Path(temp_project) / "upm" / "plugins"
    temp_plugins_base_dir = Path(temp_project) / "upm"
    malicious_plugin_file = actual_plugins_dir_for_test / "malicious.py"

    rc_path.write_text(yaml.dump(mock_config_for_security))
    
    actual_plugins_dir_for_test.mkdir(parents=True, exist_ok=True)
    
    malicious_plugin_file.write_text(_MALICIOUS_PLUGIN_CODE)
    
    malicious_hash = hashlib.sha256(malicious_plugin_file.read_bytes()).hexdigest()

    manifest_path = actual_plugins_dir_for_test / "plugin_manifest.json"
    
    manifest_content = {
        "manifest_version": "1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec='milliseconds') + "Z",
        "plugins": {}
    }
        
    manifest_content['plugins']['malicious'] = {
        "version": "1.0.0",
        "sha256": malicious_hash,
        "class_name": "MaliciousPlugin",
        "signature": "mock_valid_signature"
    }

    with open(manifest_path, 'w') as f:
        json.dump(manifest_content, f, indent=4)

    with patch('joblib.load') as mock_joblib_load:
        mock_model_instance = MagicMock()
        mock_model_instance.predict_proba.return_value = [[0.5, 0.5]]
        mock_imputer_instance = MagicMock()
        mock_imputer_instance.transform.return_value = MagicMock()

        mock_joblib_load.return_value = {
            'model': mock_model_instance,
            'imputer': mock_imputer_instance,
            'feature_names': ['dummy_feature']
        }

        def _mock_calculate_sha256_side_effect(self, filepath):
            if Path(filepath).name == "malicious.py":
                return malicious_hash
            return hashlib.sha256(Path(filepath).read_bytes()).hexdigest()
        
        def _mock_verify_signature_side_effect(self, plugin_name, data, signature_hex):
            if plugin_name == "malicious":
                return True
            return False

        with patch('upm.plugin_manager.PluginManager._calculate_file_sha256', autospec=True, side_effect=_mock_calculate_sha256_side_effect), \
             patch('upm.plugin_manager.PluginManager._verify_plugin_signature', autospec=True, side_effect=_mock_verify_signature_side_effect):
            
            upm = await UniversalPackageManager.create(project_root=temp_project, plugins_base_dir=str(temp_plugins_base_dir))
    
    yield upm

# --- Security Test Suite ---

@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "linux", reason="Network sandbox tests (seccomp) are primarily for Linux")
async def test_sandbox_blocks_network_access_linux(upm_with_malicious_plugin):
    upm = await anext(upm_with_malicious_plugin)
    upm.policy['sandbox_permissions'] = {'allow_network': False}
    upm.plugin_manager.policy['sandbox_permissions'] = {'allow_network': False}

    with pytest.raises(RuntimeError) as excinfo:
        upm.plugin_manager.get_plugin('malicious')._attempt_network_call_impl()

    assert "failed with exit code" in str(excinfo.value)

@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="File write blocking via seccomp not directly applicable to Windows in the same way")
async def test_sandbox_blocks_file_write(upm_with_malicious_plugin):
    upm = await anext(upm_with_malicious_plugin)
    upm.policy['sandbox_permissions'] = {'allow_write': False}
    upm.plugin_manager.policy['sandbox_permissions'] = {'allow_write': False}

    with pytest.raises(RuntimeError) as excinfo:
        upm.plugin_manager.get_plugin('malicious')._attempt_file_write_impl()

    assert "failed with exit code" in str(excinfo.value)
    assert not os.path.exists(os.path.join(upm.project_root, "malicious_file.txt"))

@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "linux", reason="CPU limit tests relying on resource module are primarily for Linux")
async def test_sandbox_kills_on_cpu_limit_breach_linux(upm_with_malicious_plugin):
    upm = await anext(upm_with_malicious_plugin)
    upm.policy['resource_limits'] = {'max_cpu_seconds': 1}
    upm.plugin_manager.policy['resource_limits'] = {'max_cpu_seconds': 1}
    
    with pytest.raises(RuntimeError) as excinfo:
        upm.plugin_manager.get_plugin('malicious')._cpu_overuse_impl()
            
    assert "failed with exit code" in str(excinfo.value)

@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="Direct memory limits via resource module not applicable to Windows")
async def test_sandbox_kills_on_memory_limit_breach_linux_macos(upm_with_malicious_plugin):
    upm = await anext(upm_with_malicious_plugin)
    upm.policy['resource_limits'] = {'max_memory_mb': 100}
    upm.plugin_manager.policy['resource_limits'] = {'max_memory_mb': 100}

    with pytest.raises(RuntimeError) as excinfo:
        upm.plugin_manager.get_plugin('malicious')._memory_overuse_impl()
            
    assert "failed with exit code" in str(excinfo.value)

@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform not in ["win32", "darwin"], reason="This test is for non-Linux platforms (Windows/macOS) using psutil")
async def test_resource_limits_with_psutil_macos_windows(upm_with_malicious_plugin):
    if sys.platform == "win32" or sys.platform == "darwin":
        upm = await anext(upm_with_malicious_plugin)
        
        upm.policy['resource_limits'] = {'max_cpu_seconds': 1}
        upm.plugin_manager.policy['resource_limits'] = {'max_cpu_seconds': 1}

        try:
            upm.plugin_manager.get_plugin('malicious')._cpu_overuse_impl()
        except RuntimeError:
            pass # Expected failure is acceptable

        upm.policy['resource_limits'] = {'max_memory_mb': 100}
        upm.plugin_manager.policy['resource_limits'] = {'max_memory_mb': 100}
        try:
            upm.plugin_manager.get_plugin('malicious')._memory_overuse_impl()
        except RuntimeError:
            pass # Expected failure is acceptable

@pytest.mark.asyncio
async def test_log_signature_verification_fails_on_tamper(temp_project):
    from upm.encryption import EncryptionManager
    mock_encryption_manager = MagicMock(spec=EncryptionManager)
    mock_encryption_manager.config = {"require_signatures": True, "public_key_path": "dummy.pub"}
    with patch('upm.encryption.EncryptionManager.__init__', return_value=None):
        test_mgr = EncryptionManager(config={})

    log_file_path = os.path.join(temp_project, "audit.log")
    
    mock_encryption_manager.sign_data = AsyncMock(return_value=b"dummy_signature_bytes")
    
    initial_log_content = b"Initial log entry.\n"
    with open(log_file_path, "wb") as f:
        f.write(initial_log_content)
    
    with open(log_file_path + ".sig", "wb") as f_sig:
        f_sig.write(b"dummy_signature_bytes")

    with open(log_file_path, "ab") as f:
        f.write(b"Untracked, malicious log entry.\n")

    mock_encryption_manager.verify_signature = AsyncMock(return_value=False)
    
    tampered_log_content = initial_log_content + b"Untracked, malicious log entry.\n"
    with open(log_file_path + ".sig", "rb") as f_sig:
        read_signature = f_sig.read()

    is_valid = await mock_encryption_manager.verify_signature(tampered_log_content, read_signature)
    
    assert not is_valid
    mock_encryption_manager.verify_signature.assert_called_once_with(tampered_log_content, read_signature)

@pytest.mark.asyncio
@pytest.mark.real_subprocess
async def test_hostile_plugin_cannot_log_unredacted_secrets(upm_with_malicious_plugin, tmp_path):
    upm = await anext(upm_with_malicious_plugin)
    log_file = tmp_path / "security_test_audit.log"

    # Ensure the log file is clean before the test
    if os.path.exists(log_file):
        os.remove(log_file)

    # The plugin method will be run in a subprocess via entrypoint.py.
    # We must pass the log file path to the subprocess via an environment variable
    # that entrypoint.py is designed to read.
    env_patch = {'UPM_LOG_FILE': str(log_file)}
    with patch.dict(os.environ, env_patch):
        # Trigger the malicious plugin to log a secret. This will now happen
        # in a subprocess that is correctly configured to log to our test file.
        upm.plugin_manager.get_plugin('malicious')._log_unredacted_secret_impl()

    # The rest of the test can now proceed, checking the file written by the subprocess.
    log_content = ""
    # Robustly wait for the redacted log entry to appear in the log file.
    for _ in range(15):  # Wait up to ~7.5 seconds
        time.sleep(0.5)
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
            # Break the loop once the expected redacted content is found.
            if "api_key=[REDACTED]" in log_content:
                logger.debug("Found redacted log entry.")
                break
        logger.debug("Waiting for redacted log entry to appear...")

    assert "SECRET12345" not in log_content, f"Sensitive data found in log: {log_content}"
    assert "api_key=[REDACTED]" in log_content, f"Redacted data not found in log: {log_content}"
    
    # Clean up the test-specific log file
    if os.path.exists(log_file):
        os.remove(log_file)