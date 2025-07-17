import asyncio
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
from upm.logging_utils import AUDIT_LOGGER

# Configure logger for debugging
logger = logging.getLogger("upm.plugins.mock")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

class MockPlugin(EcosystemPlugin):
    """
    Pinnacle mock plugin for UPM: production-grade, audit- and CI-ready,
    defensive, observable, and fully contract-compliant.
    """
    PLUGIN_API_VERSION = "1.0.0"
    _lock = threading.RLock()

    def __init__(self, project_root: str, cache_dir: str, policy: Dict[str, Any], fernet_lib: Any = None):
        """Initialize the mock plugin with required parameters."""
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

        # Warn if not in test environment
        if not ("pytest" in sys.modules or "unittest" in sys.modules):
            logger.warning("MockPlugin loaded outside test harness—NOT for production!")
            print("[WARNING] MockPlugin loaded outside test harness—NOT for production!", file=sys.stderr)

    def _audit(self, operation: str, message: str, success: bool = True, **meta):
        """Record an auditable operation for traceability."""
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
        """Thread-safe metric increment."""
        with self._lock:
            self.metrics[key] = self.metrics.get(key, 0) + delta
            logger.debug(f"Incremented metric {key} to {self.metrics[key]}")

    def install(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False, fail: bool = False) -> Dict[str, Any]:
        """Mock synchronous install with full audit/logging and error simulation."""
        logger.debug(f"install called with package_name={package_name}, version_constraint={version_constraint}, verbose={verbose}, fail={fail}")
        assert isinstance(package_name, str), "package_name must be a string"
        if fail:
            self._increment_metric("install_failure_total")
            msg = f"Install failed for {package_name}"
            self._audit("install", msg, success=False, package=package_name)
            logger.error(msg)
            print(f"Mock install FAILURE for: {package_name}", file=sys.stdout)
            raise PluginOperationError(msg)
        self._increment_metric("install_success_total")
        self._audit("install", f"Installed {package_name}", success=True, package=package_name, version=version_constraint)
        print(f"Mock install output: {package_name}", file=sys.stdout)
        return {
            "status": "installed",
            "package": package_name,
            "version": version_constraint,
            "plugin_id": self.mock_plugin_id,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }

    async def async_install(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False, fail: bool = False) -> Dict[str, Any]:
        """Mock async install with full audit/logging and error simulation."""
        logger.debug(f"async_install called with package_name={package_name}, version_constraint={version_constraint}, verbose={verbose}, fail={fail}")
        await asyncio.sleep(0.01)
        assert isinstance(package_name, str), "package_name must be a string"
        if fail:
            self._increment_metric("install_failure_total")
            msg = f"Async install failed for {package_name}"
            self._audit("async_install", msg, success=False, package=package_name)
            logger.error(msg)
            print(f"Async mock install FAILURE for: {package_name}", file=sys.stdout)
            raise PluginOperationError(msg)
        self._increment_metric("install_success_total")
        self._audit("async_install", f"Async installed {package_name}", success=True, package=package_name, version=version_constraint)
        print(f"Async mock install output: {package_name}", file=sys.stdout)
        return {
            "status": "async_installed",
            "package": package_name,
            "version": version_constraint,
            "plugin_id": self.mock_plugin_id,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }

    def version(self) -> Dict[str, str]:
        """Report API version."""
        logger.debug("version called")
        self._audit("version", "Reported plugin API version", success=True)
        return {"version": self.PLUGIN_API_VERSION}

    def info(self) -> Dict[str, Any]:
        """Return plugin info, count queries, audit access."""
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
        """Return plugin metadata with dynamic capabilities."""
        logger.debug("meta called")
        meta = {
            "meta": "MockPlugin metadata (absolute pinnacle test double)",
            "features": self.__introspect__()["capabilities"],
            "plugin_id": self.mock_plugin_id
        }
        self._audit("meta", "Plugin meta queried", success=True)
        return meta

    def __introspect__(self) -> Dict[str, Any]:
        """Full dynamic capability scan with audit."""
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
        """Implementation for install."""
        logger.debug(f"_install_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_install_impl", f"Install impl called for {package_name}", success=True)
        return True

    async def _uninstall_impl(self, package_name: str, verbose: bool = False) -> bool:
        """Implementation for uninstall."""
        logger.debug(f"_uninstall_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_uninstall_impl", f"Uninstall impl called for {package_name}", success=True)
        return True

    async def _upgrade_impl(self, package_name: str, version_constraint: Optional[str] = None, verbose: bool = False) -> bool:
        """Implementation for upgrade."""
        logger.debug(f"_upgrade_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_upgrade_impl", f"Upgrade impl called for {package_name}", success=True)
        return True

    async def _list_installed_impl(self, verbose: bool = False) -> Dict[str, Any]:
        """Implementation for listing installed packages."""
        logger.debug("_list_installed_impl called")
        self._audit("_list_installed_impl", "Listed installed packages", success=True)
        return {}

    async def _outdated_impl(self, verbose: bool = False) -> Dict[str, Any]:
        """Implementation for listing outdated packages."""
        logger.debug("_outdated_impl called")
        self._audit("_outdated_impl", "Listed outdated packages", success=True)
        return {}

    async def _doctor_impl(self, verbose: bool = False) -> List[Any]:
        """Implementation for doctor check."""
        logger.debug("_doctor_impl called")
        self._increment_metric("doctor_runs_total")
        self._audit("_doctor_impl", "Doctor check run", success=True)
        return []

    async def _fetch_features_impl(self, package_name: str, package_version: Union[str, None]) -> Dict[str, Any]:
        """Implementation for fetching package features."""
        logger.debug(f"_fetch_features_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_fetch_features_impl", f"Fetch features for {package_name}", success=True)
        return {}

    async def _search_impl(self, query: str, verbose: bool = False, filters: Optional[Dict[str, Any]] = None, sort_by: Optional[str] = None) -> List[Any]:
        """Implementation for searching packages."""
        logger.debug(f"_search_impl called with query={query}")
        assert isinstance(query, str), "query must be a string"
        self._audit("_search_impl", f"Search called with query '{query}'", success=True)
        return []

    async def _export_native_manifest_impl(self, packages: Dict[str, Any], verbose: bool = False) -> None:
        """Implementation for exporting manifest."""
        logger.debug("_export_native_manifest_impl called")
        self._audit("_export_native_manifest_impl", "Exported native manifest", success=True, packages=packages)
        pass

    async def _import_native_manifest_impl(self, verbose: bool = False) -> List[Any]:
        """Implementation for importing manifest."""
        logger.debug("_import_native_manifest_impl called")
        self._audit("_import_native_manifest_impl", "Imported native manifest", success=True)
        return []

    async def _collect_metrics_impl(self, verbose: bool = False) -> Dict[str, Any]:
        """Implementation for collecting metrics."""
        logger.debug("_collect_metrics_impl called")
        snapshot = copy.deepcopy(self.metrics)
        self._audit("_collect_metrics_impl", "Metrics collected", success=True)
        return snapshot

    async def _prune_impl(self, package_name: str, verbose: bool = False) -> bool:
        """Implementation for pruning packages."""
        logger.debug(f"_prune_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_prune_impl", f"Prune called for {package_name}", success=True)
        return True

    async def _publish_event_impl(self, event_type: str, event_data: Any, verbose: bool = False) -> None:
        """Implementation for publishing events."""
        logger.debug(f"_publish_event_impl called with event_type={event_type}")
        self._audit("_publish_event_impl", f"Published event {event_type}", success=True, event_data=event_data)
        pass

    async def _predict_risks_impl(self, package_name: str, package_version: str, verbose: bool = False) -> float:
        """Implementation for predicting risks."""
        logger.debug(f"_predict_risks_impl called with package_name={package_name}")
        assert isinstance(package_name, str), "package_name must be a string"
        self._audit("_predict_risks_impl", f"Predicted risks for {package_name}@{package_version}", success=True)
        return 0.0

    async def _suggest_impl(self, name: str, verbose: bool = False) -> List[Dict[str, str]]:
        """Implementation for suggesting updates or fixes."""
        logger.debug(f"_suggest_impl called with name={name}")
        assert isinstance(name, str), "name must be a string"
        self._audit("_suggest_impl", f"Suggestions for {name}", success=True)
        return []

    async def _auto_fix_impl(self, name: Optional[str] = None, verbose: bool = False, suggested_version: Optional[str] = None) -> tuple[bool, str]:
        """Implementation for auto-fixing issues."""
        logger.debug(f"_auto_fix_impl called with name={name}")
        if name:
            assert isinstance(name, str), "name must be a string"
        self._audit("_auto_fix_impl", f"Auto-fix for {name or 'general'}", success=True)
        return (True, "Mock auto-fix completed")
    
    def _log_unredacted_secret_impl(self, **kwargs):
        """A 'malicious' implementation for testing secret redaction in logs."""
        AUDIT_LOGGER.critical("Leaking sensitive data: api_key=SECRET12345")
        return "Logged a secret"

    def get_metrics_snapshot(self) -> Dict[str, Any]:
        """Deep copy of metrics for assertions."""
        logger.debug("get_metrics_snapshot called")
        snap = copy.deepcopy(self.metrics)
        self._audit("get_metrics_snapshot", "Metrics snapshot fetched", success=True)
        return snap

    def reset_metrics(self) -> None:
        """Reset all metrics to default for test runs."""
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
        """Force an error for negative-path testing."""
        logger.debug(f"simulate_error called with error_msg={error_msg}")
        self._audit("simulate_error", error_msg, success=False)
        self._increment_metric("install_failure_total")
        raise PluginOperationError(error_msg)

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Returns the entire audit log."""
        logger.debug("get_audit_log called")
        self._audit("get_audit_log", "Audit log fetched", success=True)
        return copy.deepcopy(self.metrics["audit_log"])

if __name__ == "__main__":
    logger.debug("MockPlugin module loaded directly")
    # For manual testing or debugging
    plugin = MockPlugin(project_root=".", cache_dir=".cache", policy={})
    print(f"Plugin initialized: {plugin.info()}", file=sys.stdout)