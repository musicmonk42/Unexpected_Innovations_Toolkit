# tests/test_config_manager.py

import pytest
import os
import yaml
import json
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import logging
from pathlib import Path

from upm.config_manager import UPMConfig, SENSITIVE_KEYS_ENV_MAP
from upm.logging_utils import AUDIT_LOGGER
from upm.encryption import EncryptionManager
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from pydantic import ValidationError

# --- Fixtures ---

@pytest.fixture
def temp_config_dir(tmp_path):
    """Provides a temporary directory for config files."""
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    return config_dir

@pytest.fixture
def mock_env_vars(monkeypatch):
    """Mocks environment variables for config loading."""
    monkeypatch.setenv("UPM_API_KEY", "mock_api_key_env")
    monkeypatch.setenv("UPM_EMAIL_PASSWORD", "mock_email_pass_env")
    monkeypatch.setenv("UPM_SLACK_TOKEN", "mock_slack_token_env")
    yield

@pytest.fixture
async def config_manager_instance(temp_config_dir):
    """Provides an initialized UPMConfig instance."""
    from upm.error_tracker import ErrorTracker
    error_tracker_mock = MagicMock(spec=ErrorTracker)
    error_tracker_mock.add_error = MagicMock()
    # Use the async factory to create the instance
    manager = await UPMConfig.create(
        project_root=str(temp_config_dir), 
        verbose=False, 
        error_tracker=error_tracker_mock
    )
    return manager

# --- Tests for Initialization ---

@pytest.mark.asyncio
async def test_init_success(config_manager_instance):
    """Test successful initialization."""
    # The fixture is now a fully initialized object
    # FIX: Await the coroutine fixture to get the actual object
    manager = await config_manager_instance
    assert manager.config == {}
    assert manager.policy == {}

# --- Tests for Config Loading ---

@pytest.mark.asyncio
async def test_load_config_success(temp_config_dir):
    """Test loading a valid config file."""
    config_path = temp_config_dir / ".unipkgrc"
    config_content = {
        "notifications": {"email": {"enabled": True}},
        "security": {"encrypt_data": False}
    }
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f)

    from upm.error_tracker import ErrorTracker
    manager = await UPMConfig.create(project_root=str(temp_config_dir), error_tracker=MagicMock(spec=ErrorTracker))
    
    loaded_config = manager.get_config()
    assert loaded_config["notifications"]["email"]["enabled"] is True
    assert loaded_config["security"]["encrypt_data"] is False
    assert manager.get_config() == loaded_config

@pytest.mark.asyncio
async def test_load_config_file_not_found(config_manager_instance):
    """Test handling when config file is missing."""
    # FIX: Await the coroutine fixture to get the actual object
    manager = await config_manager_instance
    await manager.load_config()
    assert manager.get_config() == {}
    manager.error_tracker.add_error.assert_not_called()

# --- Other tests for this file continue here... ---
# (The rest of the file does not need changes, as the primary fix is awaiting the fixture)
@pytest.mark.asyncio
async def test_load_policy_success(temp_config_dir):
    """Test loading a valid policy file."""
    policy_path = temp_config_dir / ".unipkgpolicy.yaml"
    policy_content = {
        "blocked_packages": ["malicious-pkg"],
        "pinned_versions": {"pip": {"requests": "2.28.1"}},
        "allowed_packages": {"pip": ["safe-pkg"]}
    }
    with open(policy_path, 'w') as f:
        yaml.dump(policy_content, f)
    
    from upm.error_tracker import ErrorTracker
    manager = await UPMConfig.create(project_root=str(temp_config_dir), error_tracker=MagicMock(spec=ErrorTracker))
    
    loaded_policy = manager.get_policy()
    assert loaded_policy["blocked_packages"] == ["malicious-pkg"]
    assert manager.get_policy() == loaded_policy