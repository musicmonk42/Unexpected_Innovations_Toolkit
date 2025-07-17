# tests/test_generate_plugin_manifest.py

import pytest
import os
import json
import subprocess
import hashlib
import sys
from datetime import datetime, timezone
import asyncio
from unittest.mock import patch, MagicMock

from upm.file_utils import calculate_sha256
from pathlib import Path

# Path to the script
SCRIPT_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "generate_plugin_manifest.py")

# --- Fixtures ---

@pytest.fixture
def temp_plugins_dir(tmp_path):
    """Provides a temporary directory mimicking the plugins structure."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    
    (plugins_dir / "pip.py").write_text("class PipPlugin: pass")
    (plugins_dir / "npm.py").write_text("class NpmPlugin: pass")
    (plugins_dir / "__init__.py").touch()
    (plugins_dir / "base.py").touch()
    
    return str(plugins_dir)

@pytest.fixture
def mock_gpg_key_id():
    """Provides a mock GPG key ID."""
    return "TESTGPGKEY123"

# --- Tests for SHA256 Calculation ---

@pytest.mark.asyncio
async def test_calculate_sha256_success(temp_plugins_dir):
    """Test successful SHA256 calculation."""
    file_path = os.path.join(temp_plugins_dir, "pip.py")
    content = "class PipPlugin: pass"
    (Path(file_path)).write_text(content)
    assert await calculate_sha256(file_path) == hashlib.sha256(content.encode()).hexdigest()

@pytest.mark.asyncio
async def test_calculate_sha256_file_not_found():
    """Test hashing a non-existent file."""
    assert await calculate_sha256("/non_existent/file.py") is None

# --- Tests for Script Execution (End-to-End) ---

@pytest.mark.real_subprocess
def test_script_execution_success(temp_plugins_dir):
    """Test running the script as subprocess to generate manifest."""
    command = [sys.executable, SCRIPT_FILE_PATH, "--plugins-dir", temp_plugins_dir]
    
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert result.returncode == 0
    assert "Successfully generated plugin manifest" in result.stdout
    
    manifest_path = os.path.join(temp_plugins_dir, "plugin_manifest.json")
    assert os.path.exists(manifest_path)
    
    with open(manifest_path, 'r') as f:
        data = json.load(f)
        assert data["manifest_version"] == "1.1.0"
        assert "plugins" in data
        assert "pip" in data["plugins"]
        assert "sha256" in data["plugins"]["pip"]

@pytest.mark.real_subprocess
def test_script_execution_with_sign(temp_plugins_dir, mock_gpg_key_id, tmp_path):
    """Test running the script as subprocess with --sign argument."""
    dummy_bin_dir = tmp_path / "dummy_bin"
    dummy_bin_dir.mkdir()
    
    dummy_gpg_executable = dummy_bin_dir / "gpg.bat"
    # FIX: The output file path is the 6th argument (%6), not the 7th.
    dummy_gpg_executable.write_text(f'@echo mock signature > %6\n@exit /b 0')

    command = [
        sys.executable, 
        SCRIPT_FILE_PATH, 
        "--plugins-dir", temp_plugins_dir, 
        "--sign", mock_gpg_key_id,
        "--gpg-path", str(dummy_gpg_executable)
    ]
    
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    
    assert result.returncode == 0
    assert "Successfully signed manifest" in result.stdout
    
    sig_file = Path(temp_plugins_dir) / "plugin_manifest.json.asc"
    assert sig_file.exists()
    assert "mock signature" in sig_file.read_text()


@pytest.mark.real_subprocess
def test_script_execution_invalid_arg(temp_plugins_dir):
    """Test script with invalid arguments."""
    command = [sys.executable, SCRIPT_FILE_PATH, "--plugins-dir", temp_plugins_dir, "--invalid"]
    
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "usage:" in result.stderr or "unrecognized arguments" in result.stderr

# --- Edge Cases and Fuzzing ---

@pytest.mark.real_subprocess
def test_generate_manifest_empty_dir(tmp_path):
    """Test generation in an empty plugins directory."""
    empty_plugins_dir = tmp_path / "empty_plugins"
    empty_plugins_dir.mkdir()
    
    command = [sys.executable, SCRIPT_FILE_PATH, "--plugins-dir", str(empty_plugins_dir)]
    
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert result.returncode == 0
    
    manifest_path = os.path.join(empty_plugins_dir, "plugin_manifest.json")
    assert os.path.exists(manifest_path)
    with open(manifest_path, 'r') as f:
        data = json.load(f)
        assert data["plugins"] == {}