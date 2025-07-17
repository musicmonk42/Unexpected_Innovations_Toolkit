# scripts/generate_plugin_manifest.py

import hashlib
import json
import os
import sys
import subprocess
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import argparse # Import argparse

# --- Conditional import for jsonschema for output validation ---
try:
    from jsonschema import validate, ValidationError
    _JSONSCHEMA_AVAILABLE = True
except ImportError:
    _JSONSCHEMA_AVAILABLE = False
    sys.stderr.write("Warning: 'jsonschema' not installed. Manifest output validation is disabled.\n")

# --- Constants ---
# Default plugins directory, can be overridden by command-line argument
DEFAULT_PLUGINS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "upm", "plugins")
MANIFEST_VERSION = "1.1.0" 

# --- NEW: JSON Schema for Manifest Validation ---
MANIFEST_SCHEMA = {
    "type": "object",
    "properties": {
        "manifest_version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
        "generated_at_utc": {"type": "string", "format": "date-time"},
        "plugins": {
            "type": "object",
            "patternProperties": {
                "^[a-zA-Z0-9_-]+$": {
                    "type": "object",
                    "properties": {
                        "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}
                    },
                    "required": ["sha256"],
                    "additionalProperties": False
                }
            },
            "additionalProperties": False
        }
    },
    "required": ["manifest_version", "generated_at_utc", "plugins"],
    "additionalProperties": False
}


def calculate_sha256(filepath: str) -> str:
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def _validate_manifest(manifest_data: Dict[str, Any]) -> bool:
    """Validates the generated manifest against the defined JSON schema."""
    if not _JSONSCHEMA_AVAILABLE:
        print("Warning: jsonschema not installed, skipping manifest validation.")
        return True
    
    try:
        validate(instance=manifest_data, schema=MANIFEST_SCHEMA)
        print("Manifest structure validated successfully against schema.")
        return True
    except ValidationError as e:
        print(f"\n--- MANIFEST VALIDATION FAILED ---")
        print(f"Error: The generated manifest does not conform to the required schema.")
        print(f"Validation Error: {e.message} at path: {'/'.join(map(str, e.path))}")
        return False
    except Exception as e:
        print(f"\n--- MANIFEST VALIDATION FAILED ---")
        print(f"An unexpected error occurred during schema validation: {e}")
        return False

def sign_manifest(manifest_path: str, signature_path: str, gpg_key_id: Optional[str] = None, gpg_path: str = "gpg") -> bool:
    """Cryptographically signs the manifest file using GPG."""
    print(f"\nAttempting to sign manifest: {manifest_path}")
    cmd = [gpg_path, "--batch", "--yes", "--armor", "--detach-sign", "--output", signature_path]
    if gpg_key_id:
        cmd.extend(["--local-user", gpg_key_id])
    cmd.append(manifest_path)

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"Successfully signed manifest to: {signature_path}")
        return True
    except FileNotFoundError:
        print(f"Error: GPG command not found at '{gpg_path}'. Please install GPG (GnuPG). Skipping signing.")
    except subprocess.CalledProcessError as e:
        print(f"Error: GPG signing failed with exit code {e.returncode}.")
        print(f"Stderr: {e.stderr.strip()}")
        print("Please ensure your GPG key is properly configured. Skipping signing.")
    except Exception as e:
        print(f"An unexpected error occurred during GPG signing: {e}. Skipping signing.")
    return False

def generate_manifest(plugins_dir: str, gpg_key_id: Optional[str] = None, gpg_path: str = "gpg") -> None:
    """Generates a JSON manifest file with SHA256 hashes and metadata for all plugins."""
    print(f"Generating plugin manifest for plugins in: {plugins_dir}")
    
    if not os.path.exists(plugins_dir):
        print(f"Error: Plugins directory not found at {plugins_dir}.")
        sys.exit(1)
        
    manifest_path = os.path.join(plugins_dir, "plugin_manifest.json")
    signature_path = os.path.join(plugins_dir, "plugin_manifest.json.asc")

    plugin_hashes: Dict[str, Any] = {}
    for filename in os.listdir(plugins_dir):
        if filename.endswith('.py') and filename not in ["__init__.py", "base.py", "isolated_runner.py"]:
            filepath = os.path.join(plugins_dir, filename)
            plugin_name = os.path.splitext(filename)[0]
            try:
                plugin_hashes[plugin_name] = {"sha256": calculate_sha256(filepath)}
                print(f"  Hashed {filename}")
            except Exception as e:
                print(f"Error hashing file {filepath}: {e}")
                sys.exit(1)
    
    final_manifest = {
        "manifest_version": MANIFEST_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "plugins": plugin_hashes
    }

    if not _validate_manifest(final_manifest):
        print("Aborting manifest generation due to validation errors.")
        sys.exit(1)

    try:
        with open(manifest_path, 'w') as f:
            json.dump(final_manifest, f, indent=2, sort_keys=True)
        print(f"\nSuccessfully generated plugin manifest to: {manifest_path}")
    except Exception as e:
        print(f"Error writing manifest file {manifest_path}: {e}")
        sys.exit(1)

    if gpg_key_id:
        sign_manifest(manifest_path, signature_path, gpg_key_id, gpg_path)
    else:
        print("\nTo cryptographically sign the manifest, run this script with --sign <GPG_KEY_ID>.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate and optionally sign the UPM plugin manifest.")
    parser.add_argument('--sign', type=str, metavar='GPG_KEY_ID',
                        help='Cryptographically sign the manifest using the specified GPG key ID or email.')
    parser.add_argument('--plugins-dir', type=str, default=DEFAULT_PLUGINS_DIR,
                        help='Path to the plugins directory.')
    parser.add_argument('--gpg-path', type=str, default='gpg',
                        help='Path to the GPG executable.')
    args = parser.parse_args()
    generate_manifest(plugins_dir=args.plugins_dir, gpg_key_id=args.sign, gpg_path=args.gpg_path)