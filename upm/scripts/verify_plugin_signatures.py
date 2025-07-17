# scripts/verify_plugin_signatures.py

import hashlib
import json
import os
import sys
import subprocess
import logging
import argparse
from typing import Dict, Any, Tuple

# --- Constants ---
PLUGINS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "upm", "plugins")
MANIFEST_PATH = os.path.join(PLUGINS_DIR, "plugin_manifest.json")
SIGNATURE_PATH = os.path.join(PLUGINS_DIR, "plugin_manifest.json.asc")
LOGGER = logging.getLogger("PluginVerifier")

# --- Setup ---

def setup_logging(log_file: str = None, verbose: bool = False):
    """Configures logging for the script."""
    level = logging.DEBUG if verbose else logging.INFO
    LOGGER.setLevel(level)
    # Prevent adding handlers multiple times if re-configured
    if not LOGGER.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        LOGGER.addHandler(handler)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            LOGGER.addHandler(file_handler)

def calculate_sha256(filepath: str) -> str:
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "ERROR_FILE_NOT_FOUND"
    except Exception as e:
        return f"ERROR_CALCULATING_HASH: {e}"

# --- Core Verification Logic ---

def verify_manifest_signature(manifest_path: str, signature_path: str) -> Tuple[bool, str]:
    """Verifies the GPG signature of the manifest file."""
    LOGGER.info("--- Verifying Manifest Signature ---")
    if not os.path.exists(signature_path):
        msg = f"Manifest signature file not found at {signature_path}. Skipping verification."
        LOGGER.warning(msg)
        return False, msg

    cmd = ["gpg", "--batch", "--verify", signature_path, manifest_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if "Good signature from" in result.stderr:
            msg = f"Manifest signature is VALID. Details: {result.stderr.strip().splitlines()[-1]}"
            LOGGER.info(msg)
            return True, msg
        else:
            msg = f"Manifest signature VERIFICATION FAILED: Unexpected GPG output. Stderr: {result.stderr.strip()}"
            LOGGER.error(msg)
            return False, msg
    except FileNotFoundError:
        msg = "GPG command not found. Please install GnuPG to enable signature verification."
        LOGGER.error(msg)
        return False, msg
    except subprocess.CalledProcessError as e:
        msg = f"Manifest signature VERIFICATION FAILED: GPG exited with code {e.returncode}. Stderr: {e.stderr.strip()}"
        LOGGER.error(msg)
        return False, msg

def verify_plugins() -> Tuple[bool, Dict[str, Any]]:
    """
    Verifies plugin integrity against the manifest and the manifest's signature.
    Returns a boolean success status and a structured result dictionary.
    """
    LOGGER.info(f"Starting plugin integrity verification for directory: {PLUGINS_DIR}")
    results: Dict[str, Any] = {
        "summary": {"overall_status": "FAIL", "issues_found": 0},
        "signature_verification": {},
        "hash_verification": {"mismatched": [], "missing_from_disk": [], "not_in_manifest": []}
    }
    
    # 1. Verify manifest signature first
    sig_ok, sig_msg = verify_manifest_signature(MANIFEST_PATH, SIGNATURE_PATH)
    results["signature_verification"] = {"status": "PASS" if sig_ok else "FAIL", "message": sig_msg}
    if not sig_ok:
        results["summary"]["issues_found"] += 1
        LOGGER.error("Halting verification due to manifest signature failure.")
        return False, results

    # 2. Proceed with hash verification
    if not os.path.exists(MANIFEST_PATH):
        LOGGER.error(f"Plugin manifest not found at {MANIFEST_PATH}.")
        results["summary"]["issues_found"] += 1
        return False, results

    try:
        with open(MANIFEST_PATH, 'r') as f:
            manifest_data = json.load(f)
            # Use the 'plugins' key from the new structured manifest
            expected_hashes = manifest_data.get("plugins", {})
    except json.JSONDecodeError as e:
        LOGGER.error(f"Invalid JSON in manifest {MANIFEST_PATH}: {e}", exc_info=True)
        results["summary"]["issues_found"] += 1
        return False, results

    LOGGER.info("--- Verifying Plugin File Hashes ---")
    found_plugins_on_disk = set()
    all_hashes_ok = True

    for filename in os.listdir(PLUGINS_DIR):
        if filename.endswith('.py') and filename not in ["__init__.py", "base.py", "isolated_runner.py"]:
            plugin_name = os.path.splitext(filename)[0]
            filepath = os.path.join(PLUGINS_DIR, filename)
            found_plugins_on_disk.add(plugin_name)

            if plugin_name not in expected_hashes:
                LOGGER.warning(f"{filename}: NOT IN MANIFEST. Possible unauthorized file.")
                results["hash_verification"]["not_in_manifest"].append(filename)
                all_hashes_ok = False
                continue

            expected_hash = expected_hashes[plugin_name].get("sha256")
            current_hash = calculate_sha256(filepath)
            
            if current_hash == expected_hash:
                LOGGER.info(f"{filename}: OK")
            else:
                LOGGER.error(f"{filename}: HASH MISMATCH! Expected {expected_hash[:12]}..., Got {current_hash[:12]}...")
                results["hash_verification"]["mismatched"].append(filename)
                all_hashes_ok = False

    # Check for files in manifest but missing from disk
    for plugin_name in expected_hashes:
        if plugin_name not in found_plugins_on_disk:
            LOGGER.error(f"{plugin_name}.py: MISSING FROM DISK.")
            results["hash_verification"]["missing_from_disk"].append(f"{plugin_name}.py")
            all_hashes_ok = False

    if all_hashes_ok:
        results["summary"]["overall_status"] = "PASS"
        LOGGER.info("✨ All plugins verified successfully against the manifest.")
    else:
        issue_count = len(results["hash_verification"]["mismatched"]) + \
                      len(results["hash_verification"]["missing_from_disk"]) + \
                      len(results["hash_verification"]["not_in_manifest"])
        results["summary"]["issues_found"] += issue_count
        LOGGER.warning("⚠️ Some plugins failed hash verification.")
        
    return all_hashes_ok, results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify UPM plugin manifest and file integrity.")
    parser.add_argument('--json', action='store_true', help='Output results in JSON format to stdout.')
    parser.add_argument('--log-file', type=str, help='Path to a file to write logs to.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging to stderr.')
    args = parser.parse_args()

    setup_logging(log_file=args.log_file, verbose=args.verbose)

    success, report = verify_plugins()

    if args.json:
        # Print the structured JSON report to stdout
        print(json.dumps(report, indent=2))
    else:
        # Print human-readable summary if not in JSON mode
        LOGGER.info("--- Verification Summary ---")
        if success:
            LOGGER.info("✅ All checks passed.")
        else:
            LOGGER.error(f"❌ Verification failed. Found {report['summary']['issues_found']} issue(s). Review logs for details.")

    # Exit with a status code appropriate for CI/CD pipelines
    sys.exit(0 if success else 1)