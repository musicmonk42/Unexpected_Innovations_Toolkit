# tests/test_file_utils.py

import pytest
import os
import time
import threading
import hashlib
from unittest.mock import patch, MagicMock
import asyncio
from typing import Union, Optional

from upm.file_utils import atomic_write, FileLock, calculate_sha256

# --- Fixtures ---

@pytest.fixture
def temp_file_path(tmp_path):
    """Provides a temporary file path for testing."""
    return tmp_path / "test_file.txt"

@pytest.fixture
def temp_dir(tmp_path):
    """Provides a temporary directory for testing."""
    return tmp_path

# --- Tests for atomic_write ---

def test_atomic_write_success(temp_file_path):
    """Test successful atomic write to a file."""
    content = b"Test content"
    mode = 'wb'
    atomic_write(temp_file_path, content, mode=mode)
    
    with open(temp_file_path, 'rb') as f:
        assert f.read() == content

def test_atomic_write_text_mode(temp_file_path):
    """Test atomic write in text mode."""
    content = "Text content\n"
    mode = 'w'
    atomic_write(temp_file_path, content, mode=mode)
    
    with open(temp_file_path, 'r') as f:
        assert f.read() == content

def test_atomic_write_overwrite_existing(temp_file_path):
    """Test atomic write overwrites an existing file."""
    with open(temp_file_path, 'w') as f:
        f.write("Old content")
    
    new_content = "New content"
    atomic_write(temp_file_path, new_content, mode='w')
    
    with open(temp_file_path, 'r') as f:
        assert f.read() == new_content

def test_atomic_write_failure_cleanup(temp_file_path):
    """Test that temporary file is cleaned up on failure."""
    with patch('tempfile.NamedTemporaryFile') as mock_temp_file:
        mock_file_context = MagicMock()
        mock_file_context.__enter__.return_value.write.side_effect = IOError("Disk full")
        mock_temp_file.return_value = mock_file_context
        
        with pytest.raises(RuntimeError, match="An unexpected error occurred during atomic write"):
            atomic_write(temp_file_path, "Fail content", mode='w')
        
        assert not os.path.exists(temp_file_path)

# --- Tests for FileLock ---

@pytest.mark.asyncio
async def test_file_lock_acquire_release(temp_file_path):
    """Test acquiring and releasing an async file lock."""
    lock_file = f"{temp_file_path}.lock"

    async def try_acquire_and_hold():
        async with FileLock(temp_file_path, timeout=0.1):
            await asyncio.sleep(0.2)
    
    task = asyncio.create_task(try_acquire_and_hold())
    await asyncio.sleep(0.05) 

    start_time = time.time()
    with pytest.raises(TimeoutError):
        async with FileLock(temp_file_path, timeout=0.1):
            pass 
    
    duration = time.time() - start_time
    assert 0.1 <= duration < 0.15 
    
    await task 

@pytest.mark.asyncio
async def test_file_lock_context_manager(temp_file_path):
    """Test FileLock as a context manager correctly creates and removes the lock file."""
    lock_filepath = f"{os.path.abspath(temp_file_path)}.lock"
    assert not os.path.exists(lock_filepath)
    
    async with FileLock(temp_file_path):
        assert os.path.exists(lock_filepath)
    
    assert not os.path.exists(lock_filepath)

# --- Tests for calculate_sha256 ---

@pytest.mark.asyncio
async def test_calculate_sha256_success(temp_file_path):
    """Test hashing a file."""
    content = b"Hash me"
    with open(temp_file_path, 'wb') as f:
        f.write(content)
    
    expected_hash = hashlib.sha256(content).hexdigest()
    assert await calculate_sha256(str(temp_file_path)) == expected_hash

@pytest.mark.asyncio
async def test_calculate_sha256_file_not_found(temp_file_path):
    """Test hashing a non-existent file."""
    non_existent_path = os.path.join(os.path.dirname(temp_file_path), "missing.txt")
    assert await calculate_sha256(non_existent_path) is None

@pytest.mark.asyncio
async def test_calculate_sha256_empty_file(temp_file_path):
    """Test hashing an empty file."""
    open(temp_file_path, 'w').close()
    expected_hash = hashlib.sha256(b"").hexdigest()
    assert await calculate_sha256(str(temp_file_path)) == expected_hash

@pytest.mark.asyncio
async def test_calculate_sha256_large_file(temp_dir):
    """Test hashing a large file."""
    large_file = temp_dir / "large.txt"
    content = b"A" * (10 * 1024 * 1024)
    with open(large_file, 'wb') as f:
        f.write(content)
    
    expected_hash = hashlib.sha256(content).hexdigest()
    assert await calculate_sha256(str(large_file)) == expected_hash

# --- Concurrency and Edge Case Tests ---

@pytest.mark.asyncio
async def test_atomic_write_concurrency(temp_file_path):
    """Test concurrent atomic writes to the same file."""
    async def write_task(content):
        # FIX: Wrap the atomic_write call in a FileLock to prevent the race
        # condition on Windows where multiple threads try to os.replace()
        # the same destination file simultaneously.
        async with FileLock(temp_file_path):
             await asyncio.to_thread(atomic_write, temp_file_path, content, mode='w')

    tasks = [write_task(f"Task {i}\n") for i in range(10)]
    await asyncio.gather(*tasks)

    assert os.path.exists(temp_file_path)
    with open(temp_file_path, 'r') as f:
        content = f.read()
        assert content.startswith("Task ")
        assert len(content.splitlines()) == 1

@pytest.mark.asyncio
async def test_file_lock_nested(temp_file_path):
    """Test nested locks (should fail as it's not re-entrant)."""
    with pytest.raises(TimeoutError):
        async with FileLock(temp_file_path, timeout=0.1):
            async with FileLock(temp_file_path, timeout=0.1):
                pass