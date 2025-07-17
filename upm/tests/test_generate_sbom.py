# tests/test_generate_sbom.py

import pytest
import os
import subprocess
import hashlib
import json
import sys
from unittest.mock import patch, MagicMock
from pathlib import Path # FIX: Import Path

# Path to the script; adjust if needed
SCRIPT_PATH = "scripts/generate_sbom.sh"

# --- Fixtures ---

@pytest.fixture
def temp_project_dir(tmp_path):
    """Provides a temporary project directory with mock requirements files."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.1\n")
    
    dev_req_file = tmp_path / "requirements-dev.txt"
    dev_req_file.write_text("pytest==7.1.2\n")
    
    return tmp_path

# --- Tests for Script Execution ---

# Skip all tests in this file if not on a Unix-like system
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Bash script tests are not supported on Windows")

@pytest.mark.real_subprocess
def test_script_execution_success(temp_project_dir, monkeypatch):
    """Test successful SBOM generation without signing."""
    def custom_mock_run(cmd, **kwargs):
        if "cyclonedx-py" in cmd:
            output_file = cmd[cmd.index('-o') + 1]
            with open(output_file, 'w') as f: json.dump({"bomFormat": "CycloneDX"}, f)
            return MagicMock(returncode=0)
        if "sha256sum" in cmd[0] or "shasum" in cmd[0]:
            return MagicMock(returncode=0, stdout="dummyhash  sbom.json")
        return subprocess.run(cmd, **kwargs)

    monkeypatch.setattr(subprocess, "run", custom_mock_run)
    monkeypatch.setattr("shutil.which", lambda x: f"/usr/bin/{x}")

    os.chdir(temp_project_dir)
    result = subprocess.run(["bash", SCRIPT_PATH], capture_output=True, text=True)
    
    assert result.returncode == 0
    assert "SBOM generated successfully" in result.stdout
    
    sbom_file = temp_project_dir / "sbom.json"
    assert sbom_file.exists()
    assert (temp_project_dir / "sbom.json.sha256").exists()

@pytest.mark.real_subprocess
def test_script_execution_with_signing(temp_project_dir, monkeypatch):
    """Test SBOM generation with --sign flag."""
    dummy_bin_dir = temp_project_dir / "dummy_bin"
    dummy_bin_dir.mkdir()
    # Create a dummy executable for gpg
    dummy_gpg_path = dummy_bin_dir / "gpg"
    dummy_gpg_path.write_text('#!/bin/sh\nif [ "$1" = "--list-secret-keys" ]; then exit 0; fi\nif [ "$1" = "--armor" ]; then echo "mock signature" > "$6"; exit 0; fi\nexit 1')
    os.chmod(dummy_gpg_path, 0o755)

    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{dummy_bin_dir}:{original_path}")

    # Mock other commands
    def custom_mock_run(cmd, **kwargs):
        if "cyclonedx-py" in cmd:
            output_file = cmd[cmd.index('-o') + 1]
            with open(output_file, 'w') as f: json.dump({"bomFormat": "CycloneDX"}, f)
            return MagicMock(returncode=0)
        if "sha256sum" in cmd[0] or "shasum" in cmd[0]:
            return MagicMock(returncode=0, stdout="dummyhash  sbom.json")
        return subprocess.run(cmd, **kwargs) # Let gpg run, as we've mocked the executable

    monkeypatch.setattr(subprocess, "run", custom_mock_run)
    monkeypatch.setattr("shutil.which", lambda x: dummy_bin_dir / x if x == 'gpg' else f"/usr/bin/{x}")

    os.chdir(temp_project_dir)
    result = subprocess.run(["bash", SCRIPT_PATH, "--sign", "MOCKGPGKEY"], capture_output=True, text=True)
    
    assert result.returncode == 0
    assert "GPG signature created" in result.stdout
    assert (temp_project_dir / "sbom.json.asc").exists()