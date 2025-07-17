# upm/tests/test_project_init.py

import pytest
import os
import shutil
import json
import yaml
from unittest.mock import patch, MagicMock
import sys
import logging
import subprocess

from upm.project_init import ProjectInitializer, ProjectInitializationError
from upm.logging_utils import AUDIT_LOGGER, flush_logs # Import flush_logs

# --- Fixtures ---

@pytest.fixture
def temp_project_root(tmp_path):
    """Provides a temporary directory that acts as the CWD for tests."""
    original_cwd = os.getcwd()
    # The initializer expects a 'templates' directory at its base_dir.
    # For tests that don't explicitly mock templates, we create a dummy one.
    (tmp_path / "templates").mkdir()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(original_cwd)

@pytest.fixture(autouse=True)
def mock_subprocess_run():
    """Mocks subprocess.run for all tests to prevent actual command execution."""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout="mock stdout", stderr="", returncode=0)
        yield mock_run

@pytest.fixture(autouse=True)
def caplog_audit(caplog):
    """Fixture to capture audit logs specifically."""
    # Ensure audit logger propagates to root handlers so caplog can see them
    AUDIT_LOGGER.propagate = True
    with caplog.at_level(logging.DEBUG, logger="unipkg_audit"):
        yield caplog
    AUDIT_LOGGER.propagate = False # Reset after test

# --- Success Path Tests ---

def test_init_project_success(temp_project_root, mock_subprocess_run, caplog_audit):
    """Test successful initialization of a basic project."""
    project_name = "my-python-app"
    initializer = ProjectInitializer(base_dir=str(temp_project_root))
    # Mock templates to avoid needing real template files for this specific test
    initializer.templates = {
        "python-basic": {
            "files": {
                "src/main.py": "print('hello')",
                "pyproject.toml": "[project]\nname='{project_name}'"
            }
        }
    }
    initializer.create_project(project_name, "python-basic")

    project_path = temp_project_root / project_name
    assert project_path.is_dir()
    assert (project_path / "src" / "main.py").is_file()
    assert (project_path / "pyproject.toml").is_file()
    assert (project_path / "pyproject.toml").read_text() == f"[project]\nname='{project_name}'"

    # FIX: Check caplog.records directly
    flush_logs() # Ensure all queued logs are processed
    assert any(f"Project '{project_name}' created successfully." in r.message for r in caplog_audit.records)

# ... (rest of the file remains unchanged) ...