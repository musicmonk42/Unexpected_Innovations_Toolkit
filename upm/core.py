# upm/core.py

import os
import sys
import asyncio
import shutil
import tempfile
import atexit
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from pydantic import BaseModel, Field

from upm.logging_utils import AUDIT_LOGGER, APP_LOGGER, shutdown_logging
from upm.config_manager import UPMConfig
from upm.manifest_manager import Manifest, Lockfile
from upm.plugin_manager import PluginManager
from upm.error_tracker import ErrorTracker
from upm.notifications import Notifier
from upm.ai_predictor import AIRiskAssessor
from upm.project_init import ProjectInitializer
from upm.docker import DockerBuilder
from upm.network_util import NetworkUtil
from upm.search_util import SearchUtil
from upm.file_utils import calculate_sha256
from upm.encryption import EncryptionManager

# Pydantic Models for API responses
class OperationResult(BaseModel):
    success: bool
    errors: List[str] = Field(default_factory=list)
    report: Optional[List[str]] = Field(default_factory=list)

class SearchResultResponse(BaseModel):
    ecosystem: str
    name: str
    version: str
    description: Optional[str] = None
    url: Optional[str] = None
    license: Optional[str] = None
    extra_data: Dict[str, Any] = Field(default_factory=dict)

class SearchOperationResult(BaseModel):
    success: bool
    errors: List[str] = Field(default_factory=list)
    search_results: List[SearchResultResponse] = Field(default_factory=list)

class ListOperationResult(BaseModel):
    success: bool
    errors: List[str] = Field(default_factory=list)
    package_map: Dict[str, Dict[str, str]] = Field(default_factory=dict)


class UniversalPackageManager:
    """
    Main orchestrator for UPM functionality.
    Use the `UniversalPackageManager.create()` async factory to get an initialized instance.
    """
    def __init__(self, project_root: Optional[str] = None, **kwargs: Any):
        # __init__ is now fully synchronous and lightweight.
        self.project_root = project_root or os.getcwd()
        self.verbose = kwargs.get("verbose", False)
        self.error_tracker = ErrorTracker(console_logging=self.verbose)
        self._is_closed = False
        atexit.register(self.shutdown)

    async def _async_init(self, plugins_base_dir: Optional[str] = None, **kwargs: Any):
        """Perform all async initialization after the instance is created."""
        self.config_manager = await UPMConfig.create(
            project_root=self.project_root, 
            verbose=self.verbose, 
            error_tracker=self.error_tracker
        )
        self.config = self.config_manager.get_config()
        self.policy = self.config_manager.get_policy()
        
        sec_cfg = self.config.get("security", {})
        self.encryption_manager = EncryptionManager(config=sec_cfg)
        
        self.manifest = Manifest(file_path=os.path.join(self.project_root, "unipkg.yaml"), error_tracker=self.error_tracker, encryption_manager=self.encryption_manager)
        self.lockfile = Lockfile(file_path=os.path.join(self.project_root, ".unipkg.lock"), error_tracker=self.error_tracker, encryption_manager=self.encryption_manager, sbom_enabled=sec_cfg.get("generate_sbom", False))
        
        plugin_cache_dir = os.path.join(self.project_root, ".upm_cache")
        os.makedirs(plugin_cache_dir, exist_ok=True)
        
        # Pass the plugins_base_dir to the PluginManager constructor
        self.plugin_manager = PluginManager(
            project_root=self.project_root, config=self.config, policy=self.policy,
            error_tracker=self.error_tracker, cache_dir=plugin_cache_dir,
            fernet_lib=self.encryption_manager.fernet,
            plugins_base_dir=plugins_base_dir
        )
        self.network_util = NetworkUtil(config=self.config)
        self.search_util = SearchUtil(plugin_manager=self.plugin_manager, network_util=self.network_util, config=self.config)
        self.ai_risk_assessor = AIRiskAssessor(verbose=self.verbose, model_path=self.config.get("ai", {}).get("model_path"), cache_dir=os.path.join(plugin_cache_dir, "ai"))
        self.project_initializer = ProjectInitializer(base_dir=self.project_root)
        self.docker_builder = DockerBuilder()
        
        try:
            self.notifier = Notifier(self.config.get("notifications", {}))
            if self.notifier: self.error_tracker.set_notifier(self.notifier)
        except Exception as e:
            self.notifier = None
            AUDIT_LOGGER.warning(f"Failed to initialize Notifier: {e}")

    @classmethod
    async def create(cls, project_root: Optional[str] = None, plugins_base_dir: Optional[str] = None, **kwargs: Any):
        """
        Asynchronously creates and initializes an instance of UniversalPackageManager.
        
        Args:
            project_root: The root directory of the project.
            plugins_base_dir: Optional base directory for plugins.
            **kwargs: Additional keyword arguments.
        """
        # To avoid duplicate kwargs, pop plugins_base_dir if it's in kwargs (since it's explicit)
        if 'plugins_base_dir' in kwargs:
            plugins_base_dir = kwargs.pop('plugins_base_dir')

        instance = cls(project_root, **kwargs)
        await instance._async_init(plugins_base_dir=plugins_base_dir, **kwargs)
        return instance
        
    def shutdown(self):
        # This synchronous method is for atexit. It finds or creates a loop.
        if not self._is_closed:
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    loop.create_task(self.close())
            except RuntimeError: # 'get_running_loop' fails if no loop is running
                asyncio.run(self.close())

    async def close(self):
        if self._is_closed: return
        if hasattr(self, 'network_util'): # Check if init completed
            await self.network_util.close()
        shutdown_logging()
        self._is_closed = True

    async def install(self, ecosystem: str, package: str, version: Optional[str] = None) -> OperationResult:
        self.error_tracker.clear_errors()
        plugin = self.plugin_manager.get_plugin(ecosystem)
        if not plugin:
            self.error_tracker.add_error(f"Ecosystem '{ecosystem}' not supported.")
            return OperationResult(success=False, errors=self.error_tracker.get_errors())
        
        try:
            success = await plugin.install(package_name=package, version_constraint=version)
            if success:
                manifest_data = await self.manifest.read()
                deps = manifest_data.setdefault("dependencies", {}).setdefault(ecosystem, [])
                existing = next((d for d in deps if d.get("name") == package), None)
                if existing: existing["version"] = version or "latest"
                else: deps.append({"name": package, "version": version or "latest"})
                await self.manifest.write(manifest_data)
        except Exception as e:
            self.error_tracker.add_error(f"Plugin error during install of '{package}': {e}")
            success = False
        
        return OperationResult(success=success, errors=self.error_tracker.get_errors())

    async def uninstall(self, ecosystem: str, package: str) -> OperationResult:
        self.error_tracker.clear_errors()
        plugin = self.plugin_manager.get_plugin(ecosystem)
        if not plugin:
            self.error_tracker.add_error(f"Ecosystem '{ecosystem}' not supported.")
            return OperationResult(success=False, errors=self.error_tracker.get_errors())
        try:
            success = await plugin.uninstall(package_name=package)
            if success:
                manifest_data = await self.manifest.read()
                deps = manifest_data.setdefault("dependencies", {}).setdefault(ecosystem, [])
                manifest_data["dependencies"][ecosystem] = [d for d in deps if d.get("name") != package]
                await self.manifest.write(manifest_data)
        except Exception as e:
            self.error_tracker.add_error(f"Plugin error during uninstall of '{package}': {e}")
            success = False
        return OperationResult(success=success, errors=self.error_tracker.get_errors())
            
    async def doctor(self) -> OperationResult:
        self.error_tracker.clear_errors()
        report: List[str] = []
        for eco, plugin in self.plugin_manager.get_all_plugins().items():
            try:
                res = await plugin.doctor(verbose=self.verbose)
                if isinstance(res, list): report.extend([f"[{eco}] {item}" for item in res])
            except Exception as e:
                report.append(f"[{eco}] Doctor check failed: {e}")
                self.error_tracker.add_error(f"Plugin '{eco}' doctor check error: {e}")
        return OperationResult(success=not self.error_tracker.has_errors(), report=report, errors=self.error_tracker.get_errors())
    
    async def search(self, ecosystem: str, query: str) -> SearchOperationResult:
        results = await self.search_util.search(ecosystem, query)
        response_results = [SearchResultResponse(**r.__dict__) for r in results]
        return SearchOperationResult(success=True, search_results=response_results)

    async def sign_config(self, config_file_path: str, private_key: Any, signature_output_path: str) -> bool:
        try:
            with open(config_file_path, 'rb') as f:
                config_data = f.read()
            signature = await self.encryption_manager.sign_data(config_data, private_key=private_key)
            if signature:
                with open(signature_output_path, 'wb') as f:
                    f.write(signature)
                return True
            return False
        except Exception as e:
            self.error_tracker.add_error(f"Failed to sign config file: {e}")
            return False