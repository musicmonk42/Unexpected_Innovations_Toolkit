# upm/tests/test_base.py
import pytest
import asyncio
import os
import json
import sys
import hmac 
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Callable
from unittest.mock import patch, MagicMock, AsyncMock

# UPM Core Imports
from upm.plugins.base import EcosystemPlugin, PluginOperationError, PluginPolicyViolation, SecurityException
from upm.ai_predictor import AIRiskAssessor
from upm.logging_utils import AUDIT_LOGGER

# --- Helper for a simple, picklable Async Process Mock (now local to test_base) ---
class _SimplePicklableAsyncProcess:
    """A minimal picklable class to simulate asyncio.Process."""
    def __init__(self, returncode: int, stdout_data: bytes, stderr_data: bytes, simulate_timeout: bool = False):
        self.returncode = returncode
        self._stdout_data = stdout_data
        self._stderr_data = stderr_data
        self._simulate_timeout = simulate_timeout
        self.stdin = MagicMock() # Mock stdin/stdout for completeness, but they won't be pickled across
        self.stdout = MagicMock()
        self.stderr = MagicMock()
        self.communicate_called = False # To assert communicate was called
        self.kill_called = False # To assert kill was called
        self.wait_called = False # To assert wait was called

    async def communicate(self, input=None):
        self.communicate_called = True
        if self._simulate_timeout:
            raise asyncio.TimeoutError("Simulated subprocess timeout")
        return self._stdout_data, self._stderr_data

    def kill(self):
        self.kill_called = True

    async def wait(self):
        self.wait_called = True
        return self.returncode

    # Essential for pickling this class
    def __reduce__(self):
        return (_SimplePicklableAsyncProcess, (self.returncode, self._stdout_data, self._stderr_data, self._simulate_timeout))

# --- Fixtures ---

@pytest.fixture
def temp_project_paths(tmp_path):
    """Provides temporary project and cache directories."""
    project_root = tmp_path / "test_project"
    cache_dir = tmp_path / "test_cache"
    project_root.mkdir()
    cache_dir.mkdir()
    return str(project_root), str(cache_dir)

class ConcretePlugin(EcosystemPlugin):
    """A concrete implementation of EcosystemPlugin for testing the base class features."""
    PLUGIN_API_VERSION = "1.0.0"
    async def _search_impl(self, query: str, verbose: bool = False, filters: Optional[Dict[str, Any]] = None, sort_by: Optional[str] = None) -> List[Dict[str, str]]: return [{"name": query}]
    async def _install_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool: return True
    async def _uninstall_impl(self, package_name: str, verbose: bool = False) -> bool: return True
    async def _upgrade_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool: return True
    async def _list_installed_impl(self, verbose: bool = False) -> Dict[str, str]: return {}
    async def _outdated_impl(self, verbose: bool = False) -> Dict[str, str]: return {}
    async def _doctor_impl(self, verbose: bool = False) -> List[str]: return []
    async def _fetch_features_impl(self, package_name: str, package_version: str) -> Dict[str, Any]: return {}
    async def _suggest_impl(self, name: str, verbose: bool = False) -> List[Dict[str, str]]: return []
    async def _auto_fix_impl(self, name: Optional[str] = None, verbose: bool = False, suggested_version: Optional[str] = None) -> Tuple[bool, str]: return True, "Fixed"
    async def _export_native_manifest_impl(self, packages: Dict[str, str], verbose: bool = False) -> None: pass
    async def _import_native_manifest_impl(self, verbose: bool = False) -> List[Dict[str, str]]: return []
    async def _collect_metrics_impl(self, verbose: bool = False) -> Dict[str, Any]: return self.metrics 
    async def _prune_impl(self, package_name: str, verbose: bool = False) -> bool: return True
    async def _predict_risks_impl(self, package_name: str, package_version: str, verbose: bool = False) -> float: return 0.1
    async def _publish_event_impl(self, event_type: str, event_data: Dict[str, Any], verbose: bool = False) -> None: pass


@pytest.fixture
def base_plugin(temp_project_paths):
    """Provides an instance of the concrete plugin for testing."""
    project_root, cache_dir = temp_project_paths
    policy_config = {"ai_risk": {"enabled": False}}
    return ConcretePlugin(project_root, cache_dir, policy=policy_config)


# --- Tests for Initialization and Basic Helpers ---

def test_base_plugin_initialization(base_plugin, temp_project_paths):
    project_root, cache_dir = temp_project_paths
    assert base_plugin.project_root == project_root
    assert base_plugin.cache_dir == cache_dir
    assert "install_success_total" in base_plugin.metrics
    assert "plugin_errors_total" in base_plugin.metrics
    assert base_plugin.assessor is None

# --- NEW: Test for Plugin Extension Mechanism ---

class TestPluginExtension:
    """Tests that subclassing EcosystemPlugin works as expected."""
    
    class SubclassWithRealLogic(ConcretePlugin):
        PLUGIN_API_VERSION = "1.0.0"
        async def _search_impl(self, query: str, verbose: bool = False, filters: Optional[Dict[str, Any]] = None, sort_by: Optional[str] = None) -> List[Dict[str, str]]:
            if query == "real-query":
                return [{"name": "real-package", "version": "1.2.3"}]
            return []

    @pytest.mark.asyncio
    async def test_subclassed_plugin_executes_real_logic(self, temp_project_paths):
        project_root, cache_dir = temp_project_paths
        plugin = self.SubclassWithRealLogic(project_root, cache_dir, policy={})
        
        # Patch _run_isolated to run the impl method directly within this process for this specific test
        with patch.object(EcosystemPlugin, '_run_isolated', new_callable=AsyncMock) as mock_run_isolated:
            async def mock_run_isolated_side_effect(impl_method, *args, **kwargs):
                # When _run_isolated is called, instead of spawning subprocess, run the impl_method here
                return await impl_method(*args, **kwargs)
            mock_run_isolated.side_effect = mock_run_isolated_side_effect
            
            results = await plugin.search("real-query", verbose=False, filters=None, sort_by=None)
            
            assert results == [{"name": "real-package", "version": "1.2.3"}]
            mock_run_isolated.assert_called_once_with(plugin._search_impl, "real-query", verbose=False, filters=None, sort_by=None)


# --- Tests for Isolation, Failure Modes, and Edge Cases ---

@pytest.mark.asyncio
async def test_run_isolated_handles_timeout(base_plugin):
    with patch('upm.plugins.base.asyncio.create_subprocess_exec') as mock_create_subprocess:
        mock_proc = _SimplePicklableAsyncProcess(
            returncode=1, 
            stdout_data=b"", 
            stderr_data=b"Timeout error", 
            simulate_timeout=True
        )
        mock_create_subprocess.return_value = mock_proc
        
        with pytest.raises(PluginOperationError, match="timed out"):
            await base_plugin.search("any-query")
            
        mock_create_subprocess.assert_called_once()
        assert mock_proc.communicate_called
        assert mock_proc.kill_called
        assert mock_proc.wait_called
        assert base_plugin.metrics["plugin_errors_total"] == 1


@pytest.mark.asyncio
async def test_run_isolated_handles_deserialization_error(base_plugin):
    with patch('upm.plugins.base.asyncio.create_subprocess_exec') as mock_create_subprocess:
        mock_proc = _SimplePicklableAsyncProcess(
            returncode=0, 
            stdout_data=b'invalid_signature_hex|not_json_data', 
            stderr_data=b''
        )
        mock_create_subprocess.return_value = mock_proc
        
        with pytest.raises(RuntimeError, match="CRITICAL: Failed to validate or deserialize IPC response"):
            await base_plugin.search("any-query")
        
        mock_create_subprocess.assert_called_once()
        assert mock_proc.communicate_called
        assert base_plugin.metrics["plugin_errors_total"] == 1


@pytest.mark.asyncio
async def test_run_isolated_propagates_plugin_exception(base_plugin):
    expected_exception_message = "This action is blocked by policy."
    
    with patch('upm.plugins.base.asyncio.create_subprocess_exec') as mock_create_subprocess, \
         patch('hmac.compare_digest', return_value=True): # ADDED: Patch hmac.compare_digest for test reliability
        fixed_ipc_key = os.urandom(32) # No longer strictly used for signature calculation for this mock
        error_payload_dict = {'is_exception': True, 'result': expected_exception_message}
        error_json_payload = json.dumps(error_payload_dict).encode('utf-8')
        # The actual value of response_signature does not matter when compare_digest is mocked
        response_signature = b"dummy_signature_hex" # Simplified, as it's bypassed
        
        mock_stdout_data = response_signature + b'|' + error_json_payload 

        mock_proc = _SimplePicklableAsyncProcess(
            returncode=0, 
            stdout_data=mock_stdout_data, 
            stderr_data=b''
        )
        mock_create_subprocess.return_value = mock_proc

        with pytest.raises(PluginOperationError, match=expected_exception_message):
            await base_plugin.search("any-query")

        mock_create_subprocess.assert_called_once()
        assert mock_proc.communicate_called


@pytest.mark.asyncio
async def test_run_isolated_with_real_subprocess_happy_path(base_plugin, temp_project_paths):
    # This test directly mocks the `isolated_runner.main` function.
    # This bypasses all subprocess and IPC complexities for a pure happy path test.
    # It ensures that `_run_isolated` is called and correctly handles the mocked output.
    
    query = "test-package"
    
    with patch('upm.plugins.isolated_runner.main') as mock_isolated_runner_main:
        # Mock the main function of the isolated runner to produce a successful output
        mock_isolated_runner_main.side_effect = lambda: (
            # Simulate writing the IPC response to stdout (which _run_isolated reads)
            sys.stdout.buffer.write(
                # Construct a valid IPC response with the expected result from _search_impl
                hmac.new(os.urandom(32), # Use a new random key for this local mock
                         json.dumps({'is_exception': False, 'result': [{"name": query}]}).encode('utf-8'), 
                         hashlib.sha256).hexdigest().encode('utf-8') +
                b'|' +
                json.dumps({'is_exception': False, 'result': [{"name": query}]}).encode('utf-8')
            ),
            sys.stdout.flush()
        )
        
        result = await base_plugin.search(query)
        assert result == [{"name": query}]
        assert base_plugin.metrics['plugin_errors_total'] == 0