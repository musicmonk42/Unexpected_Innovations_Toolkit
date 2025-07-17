# upm/encryption.py

import os
import sys
import getpass
import json
import base64
import asyncio
import tempfile
import hashlib
from typing import Optional, Dict, Any, List

# --- Conditional Imports for Cryptography ---
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.exceptions import InvalidSignature
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    _CRYPTOGRAPHY_AVAILABLE = False
    Fernet = InvalidToken = InvalidSignature = PBKDF2HMAC = rsa = ec = None

from upm.logging_utils import AUDIT_LOGGER

# --- Custom Exception Hierarchy ---
class CryptoError(Exception):
    """Base exception for cryptographic errors in this module."""
class EncryptionError(CryptoError):
    """Raised when encryption fails."""
class DecryptionError(CryptoError):
    """Raised when decryption fails due to invalid token or format."""
class SigningError(CryptoError):
    """Raised when data signing fails."""
class VerificationError(CryptoError):
    """Raised when signature verification fails."""

class EncryptionManager:
    """
    Handles advanced encryption, decryption, and digital signing for UPM.
    """
    def __init__(self, config: Dict[str, Any]):
        if not _CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("The 'cryptography' library is required. Run 'pip install cryptography'.")

        self.config = config
        self._validate_config()
        
        self.cipher_suite: Optional[Fernet] = None
        self.key_fingerprint: Optional[str] = None
        self.legacy_ciphers: Dict[str, Fernet] = {}

        if self.config.get("encrypt_data", False):
            self._initialize_cipher_suites()
        else:
            AUDIT_LOGGER.warning("Encryption is disabled. Sensitive data will be stored in plaintext.")

        if not self.config.get("require_signatures", False):
            AUDIT_LOGGER.warning("Signature verification is disabled. Data integrity will not be cryptographically verified.")

    @property
    def fernet(self) -> Optional[Fernet]:
        """Exposes the Fernet cipher suite instance for external use."""
        return self.cipher_suite

    def _validate_config(self):
        """Validates required keys in the security configuration."""
        if self.config.get("encrypt_data"):
            if not isinstance(self.config.get("salt_path"), str):
                raise ValueError("Config 'salt_path' must be a valid string path.")
            if not isinstance(self.config.get("password_env_var"), str):
                raise ValueError("Config 'password_env_var' must be a valid string for the key password.")

    def _initialize_cipher_suites(self):
        """Initializes the primary and legacy cipher suites for key rotation."""
        password = os.getenv(self.config["password_env_var"])
        if not password and sys.stdin.isatty():
            password = getpass.getpass(f"Enter encryption password (for env var '{self.config['password_env_var']}'): ")
        if not password:
            raise ValueError(f"Encryption password not found and could not be provided.")

        salt = self._load_or_generate_salt(self.config["salt_path"])
        primary_key = self._derive_key_from_password(password, salt)
        self.cipher_suite = Fernet(primary_key)
        self.key_fingerprint = hashlib.sha256(primary_key).hexdigest()[:8]

        legacy_key_config = self.config.get("legacy_keys", [])
        if not legacy_key_config and self.config.get("legacy_salt_paths"):
             legacy_key_config = [{"salt_path": path} for path in self.config.get("legacy_salt_paths", {}).values()]

        for key_info in legacy_key_config:
            if legacy_salt_path := key_info.get("salt_path"):
                if os.path.exists(legacy_salt_path):
                    with open(legacy_salt_path, 'rb') as f: legacy_salt = f.read()
                    legacy_key = self._derive_key_from_password(password, legacy_salt)
                    fingerprint = hashlib.sha256(legacy_key).hexdigest()[:8]
                    self.legacy_ciphers[fingerprint] = Fernet(legacy_key)

    @staticmethod
    def _set_secure_permissions(path: str):
        """Sets user-only read/write permissions on a file."""
        try:
            if sys.platform == "win32":
                import subprocess
                user = getpass.getuser()
                subprocess.run(["icacls", path, "/inheritance:r"], check=True, capture_output=True)
                subprocess.run(["icacls", path, "/grant", f"{user}:(F)"], check=True, capture_output=True)
            else:
                os.chmod(path, 0o600)
        except Exception as e:
            AUDIT_LOGGER.warning(f"Failed to set secure permissions on {path}: {e}")

    def _load_or_generate_salt(self, salt_path: str) -> bytes:
        """Atomically loads a salt from a file or generates a new one."""
        try:
            if os.path.exists(salt_path):
                with open(salt_path, 'rb') as f: return f.read()
            
            salt_length = self.config.get("salt_length", 16)
            salt = os.urandom(salt_length)
            os.makedirs(os.path.dirname(salt_path) or '.', exist_ok=True)
            
            with tempfile.NamedTemporaryFile(mode='wb', dir=os.path.dirname(salt_path) or '.', delete=False) as tmp_file:
                tmp_file.write(salt)
                tmp_file_path = tmp_file.name
            
            os.rename(tmp_file_path, salt_path)
            self._set_secure_permissions(salt_path)
            AUDIT_LOGGER.info(f"Generated new encryption salt at {salt_path}")
            return salt
        except (IOError, OSError) as e:
            raise IOError(f"Failed to load or generate salt at {salt_path}: {e}")

    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derives a Fernet-compatible key from a password and salt."""
        iterations = self.config.get("pbkdf2_iterations", 480000)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    async def encrypt(self, plaintext_bytes: bytes) -> bytes:
        """Asynchronously encrypts plaintext into a versioned, identifiable wrapper."""
        if not isinstance(plaintext_bytes, bytes): raise TypeError("Input must be bytes.")
        if not self.cipher_suite: return plaintext_bytes

        try:
            encrypted_data = await asyncio.to_thread(self.cipher_suite.encrypt, plaintext_bytes)
            wrapper = {
                "ver": 1,
                "kid": self.key_fingerprint,
                "data": base64.b64encode(encrypted_data).decode('utf-8')
            }
            return json.dumps(wrapper).encode('utf-8')
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt data: {e}") from e

    async def decrypt(self, wrapped_ciphertext_bytes: bytes) -> bytes:
        """Asynchronously decrypts data, handling key rotation and versioning."""
        if not isinstance(wrapped_ciphertext_bytes, bytes): raise TypeError("Input must be bytes.")
        if not self.cipher_suite: return wrapped_ciphertext_bytes

        try:
            wrapper = json.loads(wrapped_ciphertext_bytes.decode('utf-8'))
            if wrapper.get("ver") != 1: raise DecryptionError(f"Unsupported encryption version: {wrapper.get('ver')}")
            
            kid = wrapper["kid"]
            ciphertext_bytes = base64.b64decode(wrapper["data"])

            cipher = self.legacy_ciphers.get(kid) if kid != self.key_fingerprint else self.cipher_suite
            if not cipher: raise DecryptionError(f"Unknown key fingerprint '{kid}'. Cannot decrypt.")
            
            return await asyncio.to_thread(cipher.decrypt, ciphertext_bytes)
        except (InvalidToken, KeyError, json.JSONDecodeError, TypeError, ValueError) as e:
            AUDIT_LOGGER.error("Decryption failed: data is invalid, corrupted, or uses a retired key.", exc_info=True)
            raise DecryptionError("Decryption failed: data is invalid or corrupted.") from e

    async def sign_data(self, data_to_sign: bytes, password: Optional[str] = None, private_key: Any = None) -> Optional[bytes]:
        """Asynchronously signs data using the private key."""
        return await asyncio.to_thread(self._sign_data_sync, data_to_sign, password, private_key)

    def _sign_data_sync(self, data_to_sign: bytes, password: Optional[str], private_key_obj: Any) -> Optional[bytes]:
        private_key = private_key_obj
        if private_key is None:
            private_key_path = self.config.get("private_key_path")
            if not private_key_path:
                raise SigningError("No private key object provided and no 'private_key_path' in config.")
            try:
                with open(private_key_path, "rb") as f:
                    private_key = serialization.load_pem_private_key(f.read(), password.encode() if password else None)
            except FileNotFoundError:
                raise SigningError(f"Private key not found at '{private_key_path}'")
            except (ValueError, TypeError) as e:
                raise SigningError(f"Could not load or use private key from path: {e}") from e

        try:
            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(data_to_sign, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))
            else:
                raise SigningError(f"Unsupported private key type: {type(private_key).__name__}")
                
            AUDIT_LOGGER.info(f"Data successfully signed.")
            return signature
        except Exception as e:
            raise SigningError(f"Failed to sign data: {e}") from e

    async def verify_signature(self, data_to_verify: bytes, signature: bytes) -> bool:
        """Asynchronously verifies a signature against data using the public key."""
        return await asyncio.to_thread(self._verify_signature_sync, data_to_verify, signature)

    def _verify_signature_sync(self, data_to_verify: bytes, signature: bytes) -> bool:
        if not self.config.get("require_signatures"): return True
        public_key_path = self.config["public_key_path"]
        try:
            with open(public_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
                
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(signature, data_to_verify, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, data_to_verify, ec.ECDSA(hashes.SHA256()))
            else:
                raise VerificationError(f"Unsupported public key type: {type(public_key).__name__}")
                
            AUDIT_LOGGER.info(f"Signature verified successfully with key: {public_key_path}")
            return True
        except InvalidSignature:
            AUDIT_LOGGER.warning(f"Signature verification FAILED for data with key: {public_key_path}")
            return False
        except FileNotFoundError:
            raise VerificationError(f"Public key not found at '{public_key_path}'")
        except Exception as e:
            AUDIT_LOGGER.error(f"Unexpected signature verification error: {e}", exc_info=True)
            return False