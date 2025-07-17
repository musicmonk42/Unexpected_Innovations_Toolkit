# tests/test_concurrency.py

import pytest
import asyncio
import os
import json
import yaml
import shutil
from unittest.mock import MagicMock, AsyncMock, patch
import contextlib
from cryptography.fernet import InvalidToken

from hypothesis import given, strategies as st, settings

from upm.manifest_manager import Manifest, Lockfile
from upm.error_tracker import ErrorTracker
# FIX: Import DecryptionError
from upm.encryption import EncryptionManager, VerificationError, DecryptionError
from upm.file_utils import FileLock

# --- Fixtures ---

@pytest.fixture
def temp_project(tmp_path):
    return tmp_path

@pytest.fixture
def mock_error_tracker():
    mock_tracker = MagicMock(spec=ErrorTracker)
    mock_tracker.add_error = MagicMock()
    return mock_tracker

@pytest.fixture
def mock_encryption_manager():
    manager = MagicMock(spec=EncryptionManager)
    manager.fernet = MagicMock()
    manager.encrypt = AsyncMock(side_effect=lambda data: data)
    manager.decrypt = AsyncMock(side_effect=lambda data: data)
    manager.sign_data = AsyncMock(return_value=b"dummy_signature")
    manager.verify_signature = AsyncMock(return_value=True)
    manager.config = {"require_signatures": True}
    return manager

@pytest.fixture
def manifest_instance(temp_project, mock_error_tracker, mock_encryption_manager):
    manifest_path = os.path.join(temp_project, "unipkg.yaml")
    return Manifest(manifest_path, mock_error_tracker, mock_encryption_manager)

@pytest.fixture
def lockfile_instance(temp_project, mock_error_tracker, mock_encryption_manager):
    lockfile_path = os.path.join(temp_project, ".unipkg.lock")
    return Lockfile(lockfile_path, mock_error_tracker, mock_encryption_manager)

# --- Basic Functionality Tests ---

@pytest.mark.asyncio
async def test_manifest_write_read_roundtrip(manifest_instance):
    test_data = {"dependencies": {"pytest": "7.4.0"}}
    await manifest_instance.write(test_data)
    read_data = await manifest_instance.read()
    assert read_data["dependencies"] == test_data["dependencies"]

@pytest.mark.asyncio
async def test_lockfile_write_read_roundtrip(lockfile_instance):
    test_data = {"packages": [{"name": "requests", "version": "2.28.1", "hash": "abc"}], "metadata": {}}
    await lockfile_instance.write(test_data)
    read_data = await lockfile_instance.read()
    assert read_data == test_data

@pytest.mark.asyncio
async def test_quarantine_on_bad_signature(manifest_instance, mock_encryption_manager):
    mock_encryption_manager.fernet = MagicMock() 
    mock_encryption_manager.decrypt.side_effect = InvalidToken("Bad signature token")
    
    test_data = {"dependencies": {"pytest": "1.0"}}
    await manifest_instance.write(test_data)
    assert os.path.exists(manifest_instance.file_path)

    with pytest.raises(DecryptionError, match="Decryption failed: data is invalid or corrupted."):
        await manifest_instance.read()

    assert os.path.exists(manifest_instance.file_path)
    manifest_instance.error_tracker.add_error.assert_called_once()
    assert "Failed to decrypt" in manifest_instance.error_tracker.add_error.call_args[0][0]

@pytest.mark.asyncio
async def test_quarantine_on_malformed_yaml(manifest_instance):
    with open(manifest_instance.file_path, "w") as f:
        f.write("key: - value\n  - invalid: yaml:")

    data = await manifest_instance.read()
    assert data == {"dependencies": {}}
    
    assert os.path.exists(manifest_instance.file_path)
    manifest_instance.error_tracker.add_error.assert_called_once()
    assert "Failed to parse" in manifest_instance.error_tracker.add_error.call_args[0][0]

# --- High-Priority Concurrency Test ---

@pytest.mark.asyncio
async def test_concurrent_manifest_writes(temp_project, mock_error_tracker, mock_encryption_manager):
    manifest_path = os.path.join(temp_project, "concurrent_manifest.yaml")
    num_tasks = 20
    
    async def writer_task(task_id: int):
        instance = Manifest(manifest_path, mock_error_tracker, mock_encryption_manager)
        data = {"id": task_id, "dependencies": {f"pkg-{task_id}": "1.0.0"}}
        await instance.write(data)

    tasks = [writer_task(i) for i in range(num_tasks)]
    await asyncio.gather(*tasks)

    final_instance = Manifest(manifest_path, mock_error_tracker, mock_encryption_manager)
    final_data = await final_instance.read()

    assert "id" in final_data
    assert final_data["id"] in range(num_tasks)
    expected_deps = {f"pkg-{final_data['id']}": "1.0.0"}
    assert final_data["dependencies"] == expected_deps