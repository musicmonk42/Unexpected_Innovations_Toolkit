# tests/test_cli.py
import os
import sys
import json
import asyncio
import typer
import subprocess
from unittest.mock import patch, MagicMock, AsyncMock
from pathlib import Path
import pytest
import contextlib 
import yaml

from upm.cli import app_cli, __version__ 
from upm.core import UniversalPackageManager, OperationResult
from upm.logging_utils import AUDIT_LOGGER

from typer.testing import CliRunner
_TYPER_AVAILABLE_FOR_TESTS = True

from hypothesis import given, strategies as st, settings, HealthCheck

# --- Fixtures ---
@pytest.fixture
def temp_project_root(tmp_path):
    rc_path = tmp_path / ".unipkgrc"
    rc_path.write_text(yaml.dump({
        "security": {"encrypt_data": False, "require_signatures": False},
        "notifications": {"email": {"enabled": False}, "slack": {"enabled": False}}
    }))
    
    policy_path = tmp_path / ".unipkgpolicy.yaml"
    policy_path.write_text(yaml.dump({
        "blocked_packages": [],
        "allowed_packages": {"pip": ["requests"]}
    }))
    
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(original_cwd)


@pytest.fixture
def mock_upm_instance(temp_project_root):
    with patch('upm.cli.UniversalPackageManager') as MockUPM:
        mock_instance = MagicMock(spec=UniversalPackageManager)
        mock_instance.install = AsyncMock() # Configure return_value inside the test
        mock_instance.search = AsyncMock(return_value={"success": True, "search_results": [], "errors": []})
        mock_instance.doctor = AsyncMock(return_value={"success": True, "report": [], "errors": []})
        
        MockUPM.return_value = mock_instance
        yield mock_instance

# --- Standard CLI Tests ---
@pytest.mark.skipif(not _TYPER_AVAILABLE_FOR_TESTS, reason="Typer not installed")
class TestTyperCLI:
    runner = CliRunner()

    def test_version_command(self):
        result = self.runner.invoke(app_cli, ["--version"])
        assert result.exit_code == 0
        assert f"UPM Version: {__version__}" in result.stdout

    def test_command_error_handling(self, mock_upm_instance):
        # FIX: Return a Pydantic OperationResult object, not a dict
        mock_upm_instance.install.return_value = OperationResult(success=False, errors=["Simulated core error"])
        result = self.runner.invoke(app_cli, ["install", "pip", "failing-package"])
        assert result.exit_code == 1
        assert "Simulated core error" in result.stdout
        assert "Suggestion:" in result.stdout

    def test_all_help_outputs(self):
        commands = [cmd.name for cmd in app_cli.registered_commands]
        assert "install" in commands
        for command in commands:
            result = self.runner.invoke(app_cli, [command, "--help"])
            assert result.exit_code == 0, f"Help command failed for '{command}'"
            assert "Usage:" in result.stdout, f"Help text missing for '{command}'"