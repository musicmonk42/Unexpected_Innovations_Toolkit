import sys
import json
import logging
import importlib
import asyncio
import uuid
import socket
import traceback
import datetime
import os
from typing import Any, Dict, Optional, Tuple
from upm.plugins.base import EcosystemPlugin
from upm.logging_utils import configure_logging

def print_json_error(error: str, status_code: int, exception: Exception = None):
    """Print JSON error response and exit."""
    output = {
        "success": False,
        "status": "error",
        "data": {
            "error": error,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
            "request_id": str(uuid.uuid4())
        }
    }
    if exception:
        output["data"]["details"] = str(exception)
        output["data"]["traceback"] = "".join(traceback.format_tb(exception.__traceback__))
    
    # Use a basic logger in case the main one failed to configure
    local_logger = logging.getLogger("upm.entrypoint.error")
    local_logger.error(json.dumps(output))

    print(json.dumps(output), file=sys.stdout)
    sys.exit(status_code)

async def main():
    """Main entrypoint for plugin execution."""
    try:
        # Use the centralized logging configuration.
        # This ensures all loggers, including AUDIT_LOGGER, are set up correctly.
        log_file = os.environ.get("UPM_LOG_FILE")
        configure_logging(
            log_file_path=log_file,
            log_format="json",
            disable_concurrent_log_handler=True,
            verbose=True
        )
    except (OSError, IOError) as ex:
        # This block specifically handles failures in setting up the logger itself.
        print_json_error(f"Logging configuration failed: {ex}", 11, ex)

    try:
        logger = logging.getLogger("upm.entrypoint")
        
        if len(sys.argv) != 4:
            print_json_error("Usage: python entrypoint.py <plugin_class> <method> <json_args>", 2)
        
        plugin_class, method, json_args = sys.argv[1:4]
        request_id = str(uuid.uuid4())
        logger.info(f"Starting plugin execution, request_id={request_id}")
        logger.info(f"Invocation details: sys.argv={sys.argv}, cwd={os.getcwd()}, request_id={request_id}")

        try:
            args_dict = json.loads(json_args)
            logger.info(f"Parsing JSON args for plugin_class={plugin_class}, method={method}, request_id={request_id}")
        except json.JSONDecodeError as ex:
            print_json_error(f"Error parsing JSON args: {ex}", 3, ex)
        
        config_path = os.environ.get("UPM_CONFIG_PATH")
        if not config_path:
            print_json_error("UPM_CONFIG_PATH environment variable not set", 5)
        
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            logger.info(f"Loaded plugin config from {config_path}")
        except Exception as ex:
            print_json_error(f"Failed to load config from {config_path}: {ex}", 5, ex)

        registry = PluginRegistry(config)
        project_root = args_dict.get("project_root", os.getcwd())
        cache_dir = args_dict.get("cache_dir", None)
        
        plugin, error = registry.instantiate_plugin(plugin_class, project_root, cache_dir)
        if error:
            print_json_error(error, 4 if "not in config" in error else 6)
        
        allowed_methods = config["plugins"].get(plugin_class, {}).get("allowed_methods", [])
        if method not in allowed_methods:
            print_json_error(f"Method '{method}' not allowed for plugin '{plugin_class}'", 7)
        
        try:
            if method.startswith("_"):
                print_json_error(f"Method '{method}' is private and cannot be called directly", 7)
            
            method_obj = getattr(plugin, method, None)
            if not method_obj:
                print_json_error(f"Method '{method}' not found in plugin '{plugin_class}'", 8)
            
            args = args_dict.get("args", [])
            kwargs = args_dict.get("kwargs", {})
            # Map 'version' to 'version_constraint' for compatibility
            if "version" in kwargs:
                kwargs["version_constraint"] = kwargs.pop("version")
            logger.info(f"Executing method={method} with args={args}, kwargs={kwargs}, request_id={request_id}")
            
            if asyncio.iscoroutinefunction(method_obj):
                result = await method_obj(*args, **kwargs)
            else:
                result = method_obj(*args, **kwargs)
            
            output = {
                "success": True,
                "status": "success",
                "data": {
                    "result": result,
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "hostname": socket.gethostname(),
                    "pid": os.getpid(),
                    "request_id": request_id
                }
            }
            print(json.dumps(output), file=sys.stdout)
            sys.exit(0)
        except Exception as ex:
            print_json_error(f"Method execution failed: {ex}", 9, ex)
    except Exception as ex:
        print_json_error(f"Fatal uncaught error in entrypoint: {ex}", 99, ex)

class PluginRegistry:
    def __init__(self, config: Dict[str, Any]):
        self._plugin_config = config.get("plugins", {})
        self._module_cache = {}
        self._policy = config.get("policy", {
            "blocked_packages": [],
            "pinned_versions": {},
            "require_signatures": False,
            "allow_prerelease": False
        })
        self.logger = logging.getLogger("upm.entrypoint.PluginRegistry")

    def import_plugin_module(self, plugin_class: str) -> Tuple[Optional[Any], Optional[str]]:
        """Import a plugin module for the given plugin class."""
        if plugin_class not in self._plugin_config:
            error_msg = f"Plugin class '{plugin_class}' not in config: {list(self._plugin_config.keys())}"
            self.logger.error(error_msg)
            return None, error_msg
        
        module_name = self._plugin_config[plugin_class]["module"]
        if module_name in self._module_cache:
            self.logger.debug(f"Using cached module for {module_name}")
            return self._module_cache[module_name], None

        try:
            self.logger.debug(f"Attempting to import module {module_name}")
            self.logger.debug(f"Current sys.path: {sys.path}")
            mod = importlib.import_module(module_name)
            self._module_cache[module_name] = mod
            self.logger.info(f"Successfully imported module {module_name}")
            return mod, None
        except ImportError as ex:
            error_msg = f"Cannot import plugin module '{module_name}'. Error: {ex}"
            self.logger.error(error_msg, exc_info=True)
            return None, error_msg

    def instantiate_plugin(self, plugin_class: str, project_root: str, cache_dir: str = None) -> Tuple[Optional[EcosystemPlugin], Optional[str]]:
        """Instantiate a plugin with the given class."""
        module, error = self.import_plugin_module(plugin_class)
        if error:
            return None, error
        
        try:
            self.logger.info(f"Instantiating plugin_class={plugin_class}")
            plugin_cls = getattr(module, plugin_class, None)
            if not plugin_cls:
                error_msg = f"Plugin class '{plugin_class}' not found in module {self._plugin_config[plugin_class]['module']}"
                self.logger.error(error_msg)
                return None, error_msg
            plugin = plugin_cls(project_root=project_root, cache_dir=cache_dir or ".cache", policy=self._policy)
            return plugin, None
        except Exception as ex:
            error_msg = f"Plugin '{plugin_class}' instantiation failed: {ex}"
            self.logger.error(error_msg, exc_info=True)
            return None, error_msg

if __name__ == "__main__":
    asyncio.run(main())