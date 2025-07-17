# upm/file_utils.py

import os
import errno
import time
import hashlib
import tempfile
import asyncio
import sys
from typing import Union, Optional

# Conditional import for portalocker for robust, cross-platform file locking
try:
    import portalocker
    _PORTALOCKER_AVAILABLE = True
except ImportError:
    _PORTALOCKER_AVAILABLE = False


class FileLock:
    """
    An async, file-based lock context manager for inter-process synchronization.
    This provides a robust, cross-platform advisory lock.

    Usage:
        async with FileLock("/path/to/my/file.txt"):
            # Critical section for file access
            ...
    """
    def __init__(self, filepath: str, timeout: int = 30, delay: float = 0.05): # FIX: Increased default timeout to 30s, decreased delay
        """
        Initializes the file lock.

        Args:
            filepath: Path to the file to lock. The lock file will be created
                      next to it with a .lock extension.
            timeout: Maximum time in seconds to wait for the lock.
            delay: Delay in seconds between lock acquisition attempts.
        """
        self.lock_filepath = f"{os.path.abspath(filepath)}.lock"
        self.timeout = timeout
        self.delay = delay
        self._lock_file_handle = None

    async def __aenter__(self) -> None:
        """Acquires the file lock, blocking asynchronously until acquired or timed out."""
        # Ensure the directory for the lock file exists
        os.makedirs(os.path.dirname(self.lock_filepath) or '.', exist_ok=True)
        
        start_time = time.time()
        while True:
            try:
                # FIX: Implement manual retry/timeout using os.O_EXCL for cross-process atomic creation
                # This pattern is more robust for direct file-based locks, similar to provided pseudocode.
                # os.open with os.O_EXCL ensures atomic creation. If file exists, it raises FileExistsError.
                # We open in read+write mode to allow locking on Windows.
                self._lock_file_handle = await asyncio.to_thread(
                    os.open, self.lock_filepath, os.O_CREAT | os.O_EXCL | os.O_RDWR
                )
                # If portalocker is available, apply an exclusive lock to the opened file descriptor.
                # This adds another layer of robustness, especially on systems where os.O_EXCL alone
                # might not prevent *advisory* concurrent access after creation.
                if _PORTALOCKER_AVAILABLE:
                    await asyncio.to_thread(
                        portalocker.lock, 
                        self._lock_file_handle,
                        portalocker.LOCK_EX
                    )
                break # Lock acquired
            except FileExistsError:
                # File already exists, meaning another process holds the lock
                if time.time() - start_time > self.timeout:
                    raise TimeoutError(f"Failed to acquire lock for {self.lock_filepath} after {self.timeout} seconds.")
                await asyncio.sleep(self.delay) # Wait and retry
            except Exception as e:
                # Handle other potential errors during file opening or locking
                if self._lock_file_handle is not None:
                    await asyncio.to_thread(os.close, self._lock_file_handle)
                    self._lock_file_handle = None
                raise RuntimeError(f"Error during lock acquisition for {self.lock_filepath}: {e}") from e

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Releases the file lock and cleans up the lock file."""
        await self.close()

    async def close(self):
        """A helper method to ensure the lock is released and file is closed."""
        if self._lock_file_handle is not None:
            try:
                # If portalocker was used for locking the FD, unlock it first
                if _PORTALOCKER_AVAILABLE:
                    await asyncio.to_thread(portalocker.unlock, self._lock_file_handle)
            except Exception as e:
                # Log the error but continue to close the file and unlink
                sys.stderr.write(f"Warning: Error during portalocker unlock for {self.lock_filepath}: {e}\n")
            finally:
                # Close the file descriptor
                try:
                    await asyncio.to_thread(os.close, self._lock_file_handle)
                except OSError as e:
                    sys.stderr.write(f"Warning: Error closing lock file descriptor {self.lock_filepath}: {e}\n")
                self._lock_file_handle = None

                # Remove the lock file
                try:
                    os.unlink(self.lock_filepath)
                except OSError as e:
                    # Ignore file not found errors, but log others
                    if e.errno != errno.ENOENT:
                        sys.stderr.write(f"Warning: Could not unlink lock file {self.lock_filepath}: {e}\n")


def atomic_write(filepath: str, data: Union[str, bytes], mode: str = 'w', encoding: Optional[str] = 'utf-8') -> None:
    """
    Atomically writes data to a file. It creates a temporary file in the same
    directory and then renames it to ensure that the final file is never left
    in a partially written state.
    """
    if 'a' in mode or mode not in ['w', 'wb']:
        raise ValueError("Atomic write only supports 'w' and 'wb' modes.")

    if isinstance(data, str) and 'b' in mode:
        raise ValueError("Cannot write string data in binary mode 'wb'.")
    if isinstance(data, bytes) and 'b' not in mode:
        raise ValueError("Cannot write bytes data in text mode 'w'. Use 'wb'.")

    dirpath = os.path.dirname(filepath)
    os.makedirs(dirpath or '.', exist_ok=True)
    
    temp_file_path = ""
    try:
        # Create a temporary file in the same directory to ensure os.replace is atomic
        with tempfile.NamedTemporaryFile(
            mode=mode, 
            dir=dirpath, 
            delete=False, 
            encoding=encoding if 'b' not in mode else None
        ) as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            temp_file_path = tmp.name
        
        # os.replace is atomic on both Unix and modern Windows
        os.replace(temp_file_path, filepath)

    except Exception as e:
        # Clean up the temporary file on any failure
        if os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
            except OSError:
                pass
        raise RuntimeError(f"An unexpected error occurred during atomic write to '{filepath}': {e}") from e


async def calculate_sha256(filepath: str) -> Optional[str]:
    """
    Asynchronously calculates the SHA256 hash of a file by running the
    synchronous I/O in a separate thread.

    Args:
        filepath: The path to the file.

    Returns:
        The hex digest of the SHA256 hash, or None if the file cannot be read.
    """
    def _hash_sync():
        if not os.path.exists(filepath):
            return None
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(8192), b""): # Use a larger chunk size
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (IOError, OSError):
            return None

    return await asyncio.to_thread(_hash_sync)