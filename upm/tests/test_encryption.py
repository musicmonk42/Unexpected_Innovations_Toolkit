# tests/test_encryption.py

import os
import tempfile
import pytest
import asyncio
import json
import base64
import threading
from unittest.mock import patch

# --- New imports for advanced testing ---
from hypothesis import given, strategies as st, settings, HealthCheck, assume

# --- Cryptography imports ---
from upm.encryption import (
    EncryptionManager, EncryptionError, DecryptionError, SigningError, VerificationError
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# --- Utility Functions: Generate temp keypairs ---

def generate_rsa_keypair(tmpdir, password=None):
    """Generates and saves an RSA keypair for testing."""
    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    priv_path = os.path.join(tmpdir, "priv_rsa.pem")
    pub_path = os.path.join(tmpdir, "pub_rsa.pem")
    with open(priv_path, "wb") as f:
        f.write(privkey.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc
        ))
    with open(pub_path, "wb") as f:
        f.write(privkey.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return priv_path, pub_path

def generate_ecdsa_keypair(tmpdir, password=None):
    """NEW: Generates and saves an ECDSA keypair for testing."""
    privkey = ec.generate_private_key(ec.SECP256R1())
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    priv_path = os.path.join(tmpdir, "priv_ecdsa.pem")
    pub_path = os.path.join(tmpdir, "pub_ecdsa.pem")
    with open(priv_path, "wb") as f:
        f.write(privkey.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc
        ))
    with open(pub_path, "wb") as f:
        f.write(privkey.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return priv_path, pub_path

# --- Fixtures ---

@pytest.fixture
def rsa_config(monkeypatch, tmp_path):
    """Provides a standard configuration using RSA keys."""
    salt_path = os.path.join(tmp_path, "salt.bin")
    priv_path, pub_path = generate_rsa_keypair(str(tmp_path), password="testpass")
    monkeypatch.setenv("ENCRYPT_PASS", "secretpw")
    return {
        "encrypt_data": True,
        "salt_path": salt_path,
        "password_env_var": "ENCRYPT_PASS",
        "pbkdf2_iterations": 1000, # Lower for faster tests
        "require_signatures": True,
        "private_key_path": priv_path,
        "public_key_path": pub_path,
        "signature_algorithm": "RSA"
    }

# --- Core Functionality Tests ---

@pytest.mark.asyncio
async def test_encrypt_decrypt_roundtrip(rsa_config):
    mgr = EncryptionManager(rsa_config)
    data = b"my test data"
    encrypted = await mgr.encrypt(data)
    assert encrypted != data
    decrypted = await mgr.decrypt(encrypted)
    assert decrypted == data

@pytest.mark.asyncio
async def test_sign_and_verify(rsa_config):
    mgr = EncryptionManager(rsa_config)
    data = b"important message"
    sig = await mgr.sign_data(data, password="testpass")
    assert sig
    assert await mgr.verify_signature(data, sig)

@pytest.mark.asyncio
async def test_tampered_ciphertext_fails(rsa_config):
    mgr = EncryptionManager(rsa_config)
    ct = await mgr.encrypt(b"tamper test")
    dct = json.loads(ct.decode())
    dct["data"] = base64.b64encode(b"nonsense!").decode()
    tampered = json.dumps(dct).encode()
    with pytest.raises(DecryptionError):
        await mgr.decrypt(tampered)

# --- NEW: Key Rotation and Migration Test (High Priority) ---

@pytest.mark.asyncio
async def test_key_rotation_and_migration(monkeypatch, tmp_path):
    """
    Tests that data encrypted with a legacy key can be decrypted by a manager
    configured with a new key, and then re-encrypted with the new key.
    """
    monkeypatch.setenv("ROTATION_PASS", "supersecret")
    
    # 1. Setup legacy environment
    legacy_dir = tmp_path / "legacy"
    legacy_dir.mkdir()
    legacy_salt_path = legacy_dir / "legacy_salt.bin"
    legacy_priv, legacy_pub = generate_rsa_keypair(str(legacy_dir), "legacy_pass")
    legacy_config = {
        "encrypt_data": True, "salt_path": str(legacy_salt_path),
        "password_env_var": "ROTATION_PASS", "pbkdf2_iterations": 1000,
        "require_signatures": True, "private_key_path": legacy_priv,
        "public_key_path": legacy_pub, "signature_algorithm": "RSA"
    }
    legacy_mgr = EncryptionManager(legacy_config)
    original_data = b"data from the past"
    encrypted_with_legacy_key = await legacy_mgr.encrypt(original_data)
    
    # 2. Setup new environment with legacy keys configured
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    new_salt_path = new_dir / "new_salt.bin"
    new_priv, new_pub = generate_rsa_keypair(str(new_dir), "new_pass")
    new_config = {
        "encrypt_data": True, "salt_path": str(new_salt_path),
        "password_env_var": "ROTATION_PASS", "pbkdf2_iterations": 1000,
        "require_signatures": True, "private_key_path": new_priv,
        "public_key_path": new_pub, "signature_algorithm": "RSA",
        "legacy_keys": [ 
            {"salt_path": str(legacy_salt_path), "public_key_path": legacy_pub}
        ]
    }
    new_mgr = EncryptionManager(new_config)
    
    # 3. Verify decryption and re-encryption
    decrypted_data = await new_mgr.decrypt(encrypted_with_legacy_key)
    assert decrypted_data == original_data
    
    reencrypted_with_new_key = await new_mgr.encrypt(decrypted_data)
    assert reencrypted_with_new_key != encrypted_with_legacy_key
    
    final_decrypted_data = await new_mgr.decrypt(reencrypted_with_new_key)
    assert final_decrypted_data == original_data

# --- NEW: Concurrency, Algorithm, and Fuzzing Tests (Medium/Low Priority) ---

def test_multithreaded_access_is_safe(rsa_config):
    """
    Tests that a single EncryptionManager instance can be safely used
    by multiple threads concurrently without race conditions or errors.
    """
    mgr = EncryptionManager(rsa_config)
    num_threads = 10
    errors = []

    def worker():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            async def roundtrip():
                data = os.urandom(32)
                encrypted = await mgr.encrypt(data)
                decrypted = await mgr.decrypt(encrypted)
                assert data == decrypted

            loop.run_until_complete(roundtrip())
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Errors occurred during multithreaded test: {errors}"

@pytest.mark.asyncio
async def test_sign_and_verify_with_ecdsa(monkeypatch, tmp_path):
    """Tests signing and verification using the ECDSA algorithm."""
    priv_path, pub_path = generate_ecdsa_keypair(str(tmp_path), password="ecdsa_pass")
    ecdsa_config = {
        "encrypt_data": False, "require_signatures": True,
        "private_key_path": priv_path, "public_key_path": pub_path,
        "signature_algorithm": "ECDSA"
    }
    mgr = EncryptionManager(ecdsa_config)
    data = b"message signed with ecdsa"
    sig = await mgr.sign_data(data, password="ecdsa_pass")
    assert await mgr.verify_signature(data, sig)

@settings(deadline=400, derandomize=True, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(key_data=st.text())
def test_gracefully_handles_malformed_pem_keys(key_data, tmp_path):
    """Fuzzes the key loader to ensure it handles malformed PEM files."""
    assume(key_data.strip() != "")
    
    malformed_key_path = tmp_path / "bad.pem"
    malformed_key_path.write_text(key_data, encoding='utf-8', errors='ignore')
    
    config = {
        "encrypt_data": False, 
        "require_signatures": True,
        "private_key_path": str(malformed_key_path),
        "public_key_path": str(malformed_key_path),
    }
    
    # FIX: The goal is to ensure initialization doesn't crash unexpectedly.
    # It should raise a controlled error (like ValueError or our custom SigningError)
    # when the key is actually used, not necessarily on init.
    with pytest.raises((ValueError, SigningError, TypeError)):
        # Attempt to initialize and then use the manager
        mgr = EncryptionManager(config)
        # Force the key loading by attempting to sign data
        asyncio.run(mgr.sign_data(b"test data"))