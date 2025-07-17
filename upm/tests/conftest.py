# tests/conftest.py
import pytest
import os
import sys
import asyncio
import logging
import json
import yaml
import hmac
import hashlib
from unittest.mock import patch, MagicMock, AsyncMock
from pathlib import Path
from upm.logging_utils import configure_logging, AUDIT_LOGGER, shutdown_logging

# --- Core Fixtures ---
@pytest.fixture
def temp_project_root(tmp_path):
    """Provides a temporary project directory and changes cwd."""
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    
    complete_config = {
        "security": {
            "encrypt_data": False, 
            "require_signatures": False,
        },
        "notifications": {
            "email": {"enabled": False}, 
            "slack": {"enabled": False}
        },
        "ai": {
            "model_path": str(tmp_path / "mock_model.joblib")
        }
    }
    (tmp_path / ".unipkgrc").write_text(yaml.dump(complete_config))
    (tmp_path / ".unipkgpolicy.yaml").write_text(yaml.dump({"policy": {}}))
    
    yield tmp_path
    os.chdir(original_cwd)

@pytest.fixture
def mock_policy():
    """Provides a comprehensive mock policy for testing."""
    return {
        "blocked_packages": ["blocked-pkg", "malicious-pkg"],
        "allowed_packages": {"pip": ["requests", "pyyaml"], "npm": ["express", "lodash"], "cargo": ["serde"]},
        "pinned_versions": {"pip": {"requests": "2.32.4"}, "npm": {"express": "4.20.0"}, "cargo": {"serde": "1.0.100"}},
        "offline": False,
        "cache_policy": {"max_size_mb": 100, "cache_ttl_days": 30}
    }

@pytest.fixture(autouse=True)
def mock_subprocess_run(request):
    """
    Mocks subprocess.run unless a test is marked with 'real_subprocess'.
    Can also be disabled with UPM_INTEGRATION_TEST=1.
    """
    if request.node.get_closest_marker('real_subprocess') or os.environ.get("UPM_INTEGRATION_TEST"):
        yield
        return
        
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout="mock stdout", stderr="", returncode=0)
        yield mock_run

@pytest.fixture # Removed autouse=True
def mock_asyncio_subprocess_exec(request):
    """
    Mocks asyncio.create_subprocess_exec for tests that need it.
    This fixture is *not* autouse and must be requested by tests.
    It returns a MagicMock to allow flexible configuration per test.
    """
    if request.node.get_closest_marker('real_subprocess') or os.environ.get("UPM_INTEGRATION_TEST"):
        yield
        return

    with patch('asyncio.create_subprocess_exec') as mock_create_subprocess_exec_local:
        # Default behavior for this mock: successful empty process.
        mock_proc_instance = MagicMock()
        mock_proc_instance.communicate = AsyncMock(return_value=(b"", b"")) # Default to empty output
        mock_proc_instance.returncode = 0
        mock_proc_instance.kill.return_value = None
        mock_proc_instance.wait = AsyncMock(return_value=0)
        mock_create_subprocess_exec_local.return_value = mock_proc_instance
        
        yield mock_create_subprocess_exec_local # Yield the patch object itself
    
@pytest.fixture
async def mock_upm_instance(temp_project_root, mock_policy):
    """Provides a heavily mocked UniversalPackageManager instance for fast unit tests."""
    from upm.core import UniversalPackageManager
    
    with patch('upm.notifications.Notifier'), \
         patch('upm.project_init.ProjectInitializer'), \
         patch('upm.docker.DockerBuilder'), \
         patch('upm.network_util.NetworkUtil'), \
         patch('upm.search_util.SearchUtil'), \
         patch('upm.ai_predictor.AIRiskAssessor'), \
         patch('upm.config_manager.UPMConfig.create', new_callable=AsyncMock) as MockConfigCreate:

        mock_config_manager = MagicMock()
        mock_config_manager.get_config.return_value = {
            "security": {},
            "ai": {"model_path": "mock/model.joblib"} 
        }
        mock_config_manager.get_policy.return_value = mock_policy
        MockConfigCreate.return_value = mock_config_manager
        
        upm = await UniversalPackageManager.create(project_root=str(temp_project_root))
        
        upm.plugin_manager = MagicMock()
        
        yield upm

@pytest.fixture
async def real_upm_instance(temp_project_root):
    """Provides a real, unmocked UniversalPackageManager instance."""
    from upm.core import UniversalPackageManager
    yield await UniversalPackageManager.create(project_root=str(temp_project_root))