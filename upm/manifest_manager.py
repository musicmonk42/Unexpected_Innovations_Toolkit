# upm/manifest_manager.py

import os
import json
import yaml
from typing import Dict, Any, Optional
import asyncio

from upm.file_utils import FileLock, atomic_write
from upm.logging_utils import AUDIT_LOGGER
from upm.error_tracker import ErrorTracker
from upm.encryption import EncryptionManager, DecryptionError
from cryptography.fernet import InvalidToken

class _ManagedFile:
    """Base class for Manifest and Lockfile to handle common I/O and locking."""
    def __init__(self, file_path: str, error_tracker: ErrorTracker, encryption_manager: EncryptionManager):
        self.file_path = file_path
        self.error_tracker = error_tracker
        self.encryption_manager = encryption_manager
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        """Ensures the managed file and its directory exist."""
        os.makedirs(os.path.dirname(self.file_path) or '.', exist_ok=True)
        if not os.path.exists(self.file_path):
            # Write an empty structure to start
            initial_content = yaml.dump({"dependencies": {}}) if self.file_path.endswith((".yaml", ".yml")) else json.dumps({"dependencies": {}, "metadata": {}})
            atomic_write(self.file_path, initial_content, mode='w', encoding='utf-8')
            AUDIT_LOGGER.info(f"Created new file at: {self.file_path}")

    async def _read_and_decrypt(self, parser: callable) -> Dict[str, Any]:
        """Generic read and decrypt logic."""
        async with FileLock(self.file_path):
            try:
                with open(self.file_path, 'rb') as f:
                    raw_content = f.read()

                if not raw_content:
                    return {"dependencies": {}}

                # If encryption is enabled, try to decrypt first.
                if self.encryption_manager.fernet:
                    try:
                        decrypted_content = await self.encryption_manager.decrypt(raw_content)
                        return parser(decrypted_content.decode('utf-8'))
                    except (InvalidToken, DecryptionError) as e:
                        self.error_tracker.add_error(f"Failed to decrypt file {os.path.basename(self.file_path)}: {e}")
                        # Raise the specific error the test expects
                        raise DecryptionError(f"Decryption failed: data is invalid or corrupted.") from e

                # If not encrypted, parse directly.
                return parser(raw_content.decode('utf-8'))
            except (json.JSONDecodeError, yaml.YAMLError) as e:
                self.error_tracker.add_error(f"Failed to parse file '{self.file_path}': {e}")
                AUDIT_LOGGER.error(f"Parsing error for {self.file_path}: {e}", exc_info=True)
                return {"dependencies": {}}
            except Exception as e:
                # Catch other unexpected errors but don't re-raise the DecryptionError
                if not isinstance(e, DecryptionError):
                    self.error_tracker.add_error(f"An unexpected error occurred reading '{self.file_path}': {e}")
                    AUDIT_LOGGER.error(f"Unexpected error reading {self.file_path}: {e}", exc_info=True)
                # If it was a DecryptionError, it's already handled. Re-raising it.
                if isinstance(e, DecryptionError):
                     raise
                return {"dependencies": {}}

    async def _encrypt_and_write(self, data: Dict[str, Any], serializer: callable, **kwargs) -> None:
        """Generic encrypt and write logic."""
        async with FileLock(self.file_path):
            try:
                content_str = serializer(data, **kwargs)
                final_content = content_str.encode('utf-8')
                
                if self.encryption_manager.fernet:
                    final_content = await self.encryption_manager.encrypt(final_content)

                atomic_write(self.file_path, final_content, mode='wb')
                AUDIT_LOGGER.info(f"File written successfully to: {self.file_path}")
            except Exception as e:
                self.error_tracker.add_error(f"Failed to write file '{self.file_path}': {e}")
                AUDIT_LOGGER.error(f"File write error: {self.file_path}. Error: {e}", exc_info=True)

class Manifest(_ManagedFile):
    """Manages the unipkg.yaml manifest file."""
    async def read(self) -> Dict[str, Any]:
        return await self._read_and_decrypt(yaml.safe_load)

    async def write(self, data: Dict[str, Any]) -> None:
        await self._encrypt_and_write(data, yaml.dump, sort_keys=False, indent=2)

class Lockfile(_ManagedFile):
    """Manages the .unipkg.lock file."""
    def __init__(self, file_path: str, error_tracker: ErrorTracker, encryption_manager: EncryptionManager, sbom_enabled: bool = False):
        super().__init__(file_path, error_tracker, encryption_manager)
        self.sbom_enabled = sbom_enabled

    async def read(self) -> Dict[str, Any]:
        return await self._read_and_decrypt(json.loads)

    async def write(self, data: Dict[str, Any]) -> None:
        if self.sbom_enabled:
            # Placeholder for SBOM generation
            data.setdefault("metadata", {})["sbom"] = {"generated": True}
        await self._encrypt_and_write(data, json.dumps, indent=2)