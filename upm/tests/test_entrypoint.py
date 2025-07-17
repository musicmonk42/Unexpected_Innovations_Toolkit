import pytest
import json
import os
import sys
import asyncio
import logging
import subprocess
import tempfile
import uuid
import socket
from unittest.mock import Mock, patch
from io import StringIO
from pathlib import Path

# Configure logging for test debugging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        logger.debug(f"Created temporary directory: {tmpdirname}")
        yield Path(tmpdirname)

@pytest.fixture
def mock_plugin_module(temp_dir):
    """Creates a physical mock plugin file that the subprocess can import."""
    upm_dir = temp_dir / "upm"
    mock_module_path = upm_dir / "plugins"
    mock_module_path.mkdir(parents=True, exist_ok=True)
    
    # Create __init__.py files
    (upm_dir / "__init__.py").touch()
    (mock_module_path / "__init__.py").touch()
    
    mock_plugin_file = mock_module_path / "mock.py"
    mock_plugin_file.write_text(
        """import asyncio
import sys
import threading
import uuid
import datetime
import inspect
import copy
import json
import logging
from typing import Any, Dict, List, Optional, Union
from upm.plugins.base import EcosystemPlugin, PluginOperationError

logger = logging.getLogger("upm.plugins.mock")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

class MockPlugin(EcosystemPlugin):
    \"\"\"Pinnacle mock plugin for UPM: production-grade, audit- and CI-ready,
    defensive, observable, and fully contract-compliant.\"\"\"
    PLUGIN_API_VERSION = "1.0.0"
    _lock = threading.RLock()

    def __init__(self, project_root: str, cache_dir: str, policy: Dict[str, Any], fernet_lib: Any = None):
        logger.debug(f"Initializing MockPlugin with project_root={project_root}, cache_dir={cache_dir}")
        super().__init__(project_root, cache_dir, policy, fernet_lib)
        self.mock_plugin_id = str(uuid.uuid4())
        self.init_time = datetime.datetime.utcnow().isoformat() + "Z"
        with self._lock:
            for key, default in [
                ("mock_plugin_inits", 0),
                ("install_success_total", 0),
                ("install_failure_total", 0),
                ("last_error", ""),
                ("info_queries_total", 0),
                ("introspect_calls_total", 0),
                ("doctor_runs_total", 0),
                ("audit_log", []),
                ("last_operation", ""),
            ]:
                self.metrics.setdefault(key, copy.deepcopy(default))
            self.metrics["mock_plugin_inits"] += 1
            self._audit("init", f"Initialized MockPlugin {self.mock_plugin_id}", success=True)

        if not ("pytest" in sys.modules or "unittest" in sys.modules):
            logger.warning("MockPlugin loaded outside test harness—NOT for production!")
            print("[WARNING] MockPlugin loaded outside test harness—NOT for production!", file=sys.stderr)

    def _audit(self, operation: str, message: str, success: bool = True, **meta):
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "operation": operation,
            "message": message,
            "success": success,
            "caller": inspect.stack()[1].function,
            "plugin_id": self.mock_plugin_id,
        }
        if meta:
            entry.update(meta)
        with self._lock:
            self.metrics["audit_log"].append(entry)
            self.metrics["last_operation"] = operation
            if not success:
                self.metrics["last_error"] = message
            logger.debug(f"Audit: {json.dumps(entry)}")

    def _increment_metric(self, key: str, delta: int = 1):
        with self._lock:
            self.metrics[key] = self.metrics.get(key, 0) + delta
            logger.debug(f"Incremented metric {key} to {self.metrics[key]}")

    def install(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False, fail: bool = False) -> Dict[str, Any]:
        logger.debug(f"install called with package_name={package_name}, version_constraint={version_constraint}, verbose={verbose}, fail={fail}")
        assert isinstance(package_name, str), "package_name must be a string"
        if fail:
            self._increment_metric("install_failure_total")
            msg = f"Install failed for {package_name}"
            self._audit("install", msg, success=False, package=package_name)
            logger.error(msg)
            raise PluginOperationError(msg)
        self._increment_metric("install_success_total")
        self._audit("install", f"Installed {package_name}", success=True, package=package_name, version=version_constraint)
        return {
            "status": "installed",
            "package": package_name,
            "version": version_constraint,
            "plugin_id": self.mock_plugin_id,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }

    async def async_install(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False, fail: bool = False) -> Dict[str, Any]:
        logger.debug(f"async_install called with package_name={package_name}, version_constraint={version_constraint}, verbose={verbose}, fail={fail}")
        await asyncio.sleep(0.01)
        assert isinstance(package_name, str), "package_name must be a string"
        if fail:
            self._increment_metric("install_failure_total")
            msg = f"Async install failed for {package_name}"
            self._audit("async_install", msg, success=False, package=package_name)
            logger.error(msg)
            raise PluginOperationError(msg)
        self._increment_metric("install_success_total")
        self._audit("async_install", f"Async installed {package_name}", success=True, package=package_name, version=version_constraint)
        return {
            "status": "async_installed",
            "package": package_name,
            "version": version_constraint,
            "plugin_id": self.mock_plugin_id,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }

    def version(self) -> Dict[str, str]:
        logger.debug("version called")
        self._audit("version", "Reported plugin API version", success=True)
        return {
            "version": self.PLUGIN_API_VERSION,
            "plugin_id": self.mock_plugin_id
        }

    def info(self) -> Dict[str, Any]:
        logger.debug("info called")
        self._increment_metric("info_queries_total")
        self._audit("info", "Plugin info queried", success=True)
        return {
            "info": "MockPlugin (pinnacle industry-grade test double)",
            "plugin_id": self.mock_plugin_id,
            "api_version": self.PLUGIN_API_VERSION,
            "init_time": self.init_time
        }

    def meta(self) -> Dict[str, Any]:
        logger.debug("meta called")
        meta = {
            "meta": "MockPlugin metadata (absolute pinnacle test double)",
            "features": self.__introspect__()["capabilities"],
            "plugin_id": self.mock_plugin_id
        }
        self._audit("meta", "Plugin meta queried", success=True)
        return meta

    def __introspect__(self) -> Dict[str, Any]:
        logger.debug("__introspect__ called")
        self._increment_metric("introspect_calls_total")
        methods = []
        for name, obj in inspect.getmembers(self, predicate=inspect.ismethod):
            if not name.startswith("_") or name in (
                "_install_impl", "_uninstall_impl", "_upgrade_impl", "_list_installed_impl",
                "_outdated_impl", "_doctor_impl", "_fetch_features_impl", "_search_impl",
                "_export_native_manifest_impl", "_import_native_manifest_impl",
                "_collect_metrics_impl", "_prune_impl", "_publish_event_impl",
                "_suggest_impl", "_auto_fix_impl", "_predict_risks_impl"
            ):
                methods.append(name)
        self._audit("__introspect__", f"Capabilities introspected: {methods}", success=True)
        return {
            "capabilities": sorted(set(methods)),
            "api_version": self.PLUGIN_API_VERSION,
            "plugin_id": self.mock_plugin_id,
        }

    async def _install_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool:
        logger.debug(f"_install_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_install_impl", f"Install impl called for {package_name}", success=True)
        return True

    async def _uninstall_impl(self, package_name: str, verbose: bool = False) -> bool:
        logger.debug(f"_uninstall_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_uninstall_impl", f"Uninstall impl called for {package_name}", success=True)
        return True

    async def _upgrade_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool:
        logger.debug(f"_upgrade_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_upgrade_impl", f"Upgrade impl called for {package_name}", success=True)
        return True

    async def _list_installed_impl(self, verbose: bool = False) -> Dict[str, Any]:
        logger.debug("_list_installed_impl called")
        self._audit("_list_installed_impl", "Listed installed packages", success=True)
        return {}

    async def _outdated_impl(self, verbose: bool = False) -> Dict[str, Any]:
        logger.debug("_outdated_impl called")
        self._audit("_outdated_impl", "Listed outdated packages", success=True)
        return {}

    async def _doctor_impl(self, verbose: bool = False) -> List[Any]:
        logger.debug("_doctor_impl called")
        self._increment_metric("doctor_runs_total")
        self._audit("_doctor_impl", "Doctor check run", success=True)
        return []

    async def _fetch_features_impl(self, package_name: str, package_version: Union[str, None]) -> Dict[str, Any]:
        logger.debug(f"_fetch_features_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_fetch_features_impl", f"Fetch features for {package_name}", success=True)
        return {}

    async def _search_impl(self, query: str, verbose: bool = False, filters: Optional[Dict[str, Any]] = None, sort_by: Optional[str] = None) -> List[Any]:
        logger.debug(f"_search_impl called with query={query}")
        assert isinstance(query, str), "query must be a string"
        self._audit("_search_impl", f"Search called with query '{query}'", success=True)
        return []

    async def _export_native_manifest_impl(self, packages: Dict[str, Any], verbose: bool = False) -> None:
        logger.debug("_export_native_manifest_impl called")
        self._audit("_export_native_manifest_impl", "Exported native manifest", success=True, packages=packages)
        pass

    async def _import_native_manifest_impl(self, verbose: bool = False) -> List[Any]:
        logger.debug("_import_native_manifest_impl called")
        self._audit("_import_native_manifest_impl", "Imported native manifest", success=True)
        return []

    async def _collect_metrics_impl(self, verbose: bool = False) -> Dict[str, Any]:
        logger.debug("_collect_metrics_impl called")
        snapshot = copy.deepcopy(self.metrics)
        self._audit("_collect_metrics_impl", "Metrics collected", success=True)
        return snapshot

    async def _prune_impl(self, package_name: str, verbose: bool = False) -> bool:
        logger.debug(f"_prune_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_prune_impl", f"Prune called for {package_name}", success=True)
        return True

    async def _publish_event_impl(self, event_type: str, event_data: Any, verbose: bool = False) -> None:
        logger.debug(f"_publish_event_impl called with event_type={event_type}")
        self._audit("_publish_event_impl", f"Published event {event_type}", success=True, event_data=event_data)
        pass

    async def _predict_risks_impl(self, package_name: str, package_version: str, verbose: bool = False) -> float:
        logger.debug(f"_predict_risks_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_predict_risks_impl", f"Predicted risks for {package_name}@{package_version}", success=True)
        return 0.0

    async def _suggest_impl(self, name: str, verbose: bool = False) -> List[Dict[str, str]]:
        logger.debug(f"_suggest_impl called with name={name}")
        assert isinstance(name, str), "name must be a string"
        self._audit("_suggest_impl", f"Suggestions for {name}", success=True)
        return []

    async def _auto_fix_impl(self, name: Optional[str] = None, verbose: bool = False, suggested_version: Optional[str] = None) -> tuple[bool, str]:
        logger.debug(f"_auto_fix_impl called with name={name}")
        if name:
            assert isinstance(name, str), "name must be a string"
        self._audit("_auto_fix_impl", f"Auto-fix for {name or 'general'}", success=True)
        return (True, "Mock auto-fix completed")

    def get_metrics_snapshot(self) -> Dict[str, Any]:
        logger.debug("get_metrics_snapshot called")
        snap = copy.deepcopy(self.metrics)
        self._audit("get_metrics_snapshot", "Metrics snapshot fetched", success=True)
        return snap

    def reset_metrics(self) -> None:
        logger.debug("reset_metrics called")
        with self._lock:
            for k in self.metrics:
                if isinstance(self.metrics[k], int):
                    self.metrics[k] = 0
                elif isinstance(self.metrics[k], str):
                    self.metrics[k] = ""
                elif isinstance(self.metrics[k], list):
                    self.metrics[k] = []
                else:
                    self.metrics[k] = None
            self._audit("reset_metrics", "Metrics reset", success=True)

    def simulate_error(self, error_msg: str = "Simulated error") -> None:
        logger.debug(f"simulate_error called with error_msg={error_msg}")
        self._audit("simulate_error", error_msg, success=False)
        self._increment_metric("install_failure_total")
        raise PluginOperationError(error_msg)

    def get_audit_log(self) -> List[Dict[str, Any]]:
        logger.debug("get_audit_log called")
        self._audit("get_audit_log", "Audit log fetched", success=True)
        return copy.deepcopy(self.metrics["audit_log"])

if __name__ == "__main__":
    logger.debug("MockPlugin module loaded directly")
    plugin = MockPlugin(project_root=".", cache_dir=".cache", policy={})
    print(f"Plugin initialized: {plugin.info()}", file=sys.stdout)
"""
    )
    
    logger.debug(f"Created mock plugin at: {mock_plugin_file}")
    logger.debug(f"Mock plugin content:\n{mock_plugin_file.read_text()}")
    logger.debug(f"Directory structure: {list(temp_dir.rglob('*'))}")
    
    return temp_dir

@pytest.fixture
def config_file(temp_dir):
    """Create a mock config file for plugin whitelisting."""
    config_path = temp_dir / "upm_config.json"
    config = {
        "plugins": {
            "MockPlugin": {
                "module": "upm.plugins.mock",
                "allowed_methods": ["install", "async_install", "version", "info", "meta", "__introspect__"]
            },
            "PipPlugin": {
                "module": "upm.plugins.pip",
                "allowed_methods": ["install", "uninstall", "list", "version", "info", "meta"]
            },
            "NpmPlugin": {
                "module": "upm.plugins.npm",
                "allowed_methods": ["install", "uninstall", "list", "version", "info", "meta"]
            }
        },
        "policy": {
            "blocked_packages": [],
            "pinned_versions": {},
            "require_signatures": False,
            "allow_prerelease": False
        }
    }
    config_path.write_text(json.dumps(config))
    logger.debug(f"Config file created at: {config_path}")
    logger.debug(f"Config content: {config_path.read_text()}")
    return config_path

@pytest.fixture
def log_file(temp_dir):
    """Provide a log file path for capturing logs."""
    log_path = temp_dir / "entrypoint.log"
    logger.debug(f"Log file path: {log_path}")
    return log_path

def run_entrypoint(args, temp_dir, config_path=None, log_file=None):
    """Helper to run entrypoint.py as a subprocess with correct environment."""
    env = os.environ.copy()
    if config_path:
        env["UPM_CONFIG_PATH"] = str(config_path)
    if log_file:
        env["UPM_LOG_FILE"] = str(log_file)

    upm_dir = Path(__file__).parent.parent
    project_root = upm_dir.parent
    entrypoint_script_path = upm_dir / "plugins" / "entrypoint.py"
    
    python_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{str(project_root)}{os.pathsep}{str(temp_dir)}{os.pathsep}{python_path}"
    
    logger.debug(f"Running entrypoint with PYTHONPATH: {env['PYTHONPATH']}")
    logger.debug(f"Entrypoint script path: {entrypoint_script_path}")
    logger.debug(f"Command: {[sys.executable] + args}")
    
    cmd = [sys.executable, str(entrypoint_script_path)] + args
    result = subprocess.run(
        cmd, capture_output=True, text=True, env=env
    )
    logger.debug(f"Subprocess result: returncode={result.returncode}, stdout={result.stdout}, stderr={result.stderr}")
    return result

def parse_json_output(output):
    """Parse JSON output from subprocess, stripping non-JSON lines."""
    lines = output.splitlines()
    json_lines = [line for line in lines if line.strip().startswith('{')]
    if not json_lines:
        logger.error(f"No JSON found in output: {output}")
        pytest.fail(f"No JSON found in output: {output}")
    json_output = json_lines[0]
    try:
        return json.loads(json_output)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON output: {json_output}, error: {e}")
        pytest.fail(f"Failed to parse JSON output: {json_output}, error: {e}")

def check_log_file(log_file, request_id, expected_messages):
    """Check log file for expected messages."""
    try:
        with open(log_file, "r") as f:
            logs = f.read()
    except FileNotFoundError:
        logger.error(f"Log file not found: {log_file}")
        pytest.fail(f"Log file not found: {log_file}")
    for msg in expected_messages:
        assert msg in logs, f"Expected log message not found: {msg}"
    if request_id:
        assert request_id in logs, f"Request ID {request_id} not found in logs"

@pytest.mark.asyncio
@pytest.mark.real_subprocess
async def test_successful_execution(temp_dir, mock_plugin_module, config_file, log_file):
    """Test successful plugin method execution."""
    args = [
        "MockPlugin",
        "install",
        json.dumps({"project_root": str(temp_dir), "args": ["requests"], "kwargs": {"version_constraint": "2.28.1"}})
    ]
    result = run_entrypoint(args, temp_dir=mock_plugin_module, config_path=config_file, log_file=log_file)
    
    assert result.returncode == 0, f"Subprocess failed with stderr: {result.stderr}"
    output = parse_json_output(result.stdout)
    assert output["success"] is True
    assert output["data"]["result"]["status"] == "installed"
    assert output["data"]["result"]["package"] == "requests"
    assert "plugin_id" in output["data"]["result"]
    assert "timestamp" in output["data"]["result"]

@pytest.mark.asyncio
@pytest.mark.real_subprocess
async def test_async_execution(temp_dir, mock_plugin_module, config_file, log_file):
    """Test successful async plugin method execution."""
    args = [
        "MockPlugin",
        "async_install",
        json.dumps({"project_root": str(temp_dir), "args": ["requests"], "kwargs": {"version_constraint": "2.28.1"}})
    ]
    result = run_entrypoint(args, temp_dir=mock_plugin_module, config_path=config_file, log_file=log_file)
    
    assert result.returncode == 0, f"Subprocess failed with stderr: {result.stderr}"
    output = parse_json_output(result.stdout)
    assert output["success"] is True
    assert output["data"]["result"]["status"] == "async_installed"
    assert output["data"]["result"]["package"] == "requests"
    assert "plugin_id" in output["data"]["result"]
    assert "timestamp" in output["data"]["result"]

@pytest.mark.real_subprocess
@pytest.mark.parametrize("method", ["version", "info", "meta"])
def test_introspection_methods(temp_dir, mock_plugin_module, config_file, log_file, method):
    """Test introspection methods."""
    args = ["MockPlugin", method, json.dumps({"args": [], "kwargs": {}})]
    result = run_entrypoint(args, temp_dir=mock_plugin_module, config_path=config_file, log_file=log_file)
    
    assert result.returncode == 0, f"Subprocess failed with stderr: {result.stderr}"
    output = parse_json_output(result.stdout)
    assert output["success"] is True
    assert method in output["data"]["result"]
    if method != "version":
        assert "plugin_id" in output["data"]["result"]

@pytest.mark.real_subprocess
def test_introspect_private_method(temp_dir, mock_plugin_module, config_file, log_file):
    """Test that __introspect__ is rejected as a private method."""
    args = ["MockPlugin", "__introspect__", json.dumps({"args": [], "kwargs": {}})]
    result = run_entrypoint(args, temp_dir=mock_plugin_module, config_path=config_file, log_file=log_file)
    
    assert result.returncode == 7, f"Expected private method error, got returncode={result.returncode}, stderr={result.stderr}"
    output = parse_json_output(result.stdout)
    assert output["success"] is False
    assert "Method '__introspect__' is private and cannot be called directly" in output["data"]["error"]

@pytest.mark.real_subprocess
def test_invalid_args_count(temp_dir, mock_plugin_module, config_file, log_file):
    """Test error handling for invalid argument count."""
    args = ["MockPlugin", "install"]
    result = run_entrypoint(args, temp_dir=mock_plugin_module, config_path=config_file, log_file=log_file)
    
    assert result.returncode == 2
    output = parse_json_output(result.stdout)
    assert "Usage: python entrypoint.py" in output["data"]["error"]

@pytest.mark.real_subprocess
def test_invalid_json(temp_dir, mock_plugin_module, config_file, log_file):
    """Test error handling for invalid JSON args."""
    args = ["MockPlugin", "install", "invalid_json"]
    result = run_entrypoint(args, temp_dir=mock_plugin_module, config_path=config_file, log_file=log_file)
    
    assert result.returncode == 3
    output = parse_json_output(result.stdout)
    assert "Error parsing JSON args" in output["data"]["error"]

@pytest.mark.real_subprocess
def test_missing_plugin(temp_dir, mock_plugin_module, config_file, log_file):
    """Test error handling for missing plugin."""
    args = ["NonExistentPlugin", "install", json.dumps({"args": [], "kwargs": {}})]
    result = run_entrypoint(args, temp_dir=mock_plugin_module, config_path=config_file, log_file=log_file)
    
    assert result.returncode == 4
    output = parse_json_output(result.stdout)
    assert "Plugin class 'NonExistentPlugin' not in config" in output["data"]["error"]

@pytest.mark.real_subprocess
def test_unallowed_method(temp_dir, mock_plugin_module, config_file, log_file):
    """Test error handling for unallowed method."""
    args = ["MockPlugin", "unallowed_method", json.dumps({"args": [], "kwargs": {}})]
    result = run_entrypoint(args, temp_dir=mock_plugin_module, config_path=config_file, log_file=log_file)
    
    assert result.returncode == 7
    output = parse_json_output(result.stdout)
    assert "Method 'unallowed_method' not allowed" in output["data"]["error"]

@pytest.mark.real_subprocess
def test_fatal_error(temp_dir, mock_plugin_module, config_file, log_file):
    """Test handling of fatal uncaught errors by using an invalid config path."""
    invalid_config_path = "Z:\\non_existent_dir\\invalid_config.json"
    args = ["MockPlugin", "install", json.dumps({"args": ["requests"], "kwargs": {}})]
    env = os.environ.copy()
    env["UPM_CONFIG_PATH"] = invalid_config_path
    env["UPM_LOG_FILE"] = str(log_file)
    upm_dir = Path(__file__).parent.parent
    project_root = upm_dir.parent
    env["PYTHONPATH"] = f"{str(project_root)}{os.pathsep}{str(temp_dir)}{os.pathsep}{env.get('PYTHONPATH', '')}"
    cmd = [sys.executable, str(upm_dir / "plugins" / "entrypoint.py")] + args
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    
    assert result.returncode == 5
    output = parse_json_output(result.stdout)
    assert "Failed to load config" in output["data"]["error"]

@pytest.mark.real_subprocess
def test_logging_config_error(temp_dir, mock_plugin_module, config_file):
    """Test error handling for logging configuration issues by passing an invalid log file path."""
    invalid_log_file = "Z:\\non_existent_dir\\cant_create.log"
    args = ["MockPlugin", "install", json.dumps({"args": ["requests"], "kwargs": {}})]
    result = run_entrypoint(args, temp_dir=mock_plugin_module, config_path=config_file, log_file=invalid_log_file)
    
    assert result.returncode == 11
    output = parse_json_output(result.stdout)
    assert "Logging configuration failed" in output["data"]["error"]