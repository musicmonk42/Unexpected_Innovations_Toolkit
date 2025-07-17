import argparse
import sys
import os
import logging
from pathlib import Path
try:
    from upm.encryption import EncryptionManager
    from upm.logging_utils import AUDIT_LOGGER
except ImportError as e:
    print(f"Error: Could not import UPM components. Ensure '{os.path.dirname(os.path.dirname(__file__))}' is in your Python path. Details: {e}", file=sys.stdout)
    sys.exit(1)

# Configure logging
logger = logging.getLogger("unipkg_audit")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

def sign_config(config_path: str, private_key_path: str, verbose: bool = False):
    """Sign a configuration file using the provided private key."""
    if verbose:
        logger.info("Verbose mode enabled.")
        logger.info(f"Attempting to sign configuration file: {config_path}")

    config_path = os.path.abspath(config_path)
    private_key_path = os.path.abspath(private_key_path)

    if not os.path.exists(config_path):
        print(f"Error: Config file not found at {config_path}", file=sys.stdout)
        sys.exit(1)

    try:
        with open(config_path, "rb") as f:
            config_data = f.read()
    except Exception as e:
        print(f"Error: Failed to read config file {config_path}: {e}", file=sys.stdout)
        sys.exit(1)

    try:
        encryption_manager = EncryptionManager(config={"private_key_path": private_key_path})
        signature = encryption_manager.sign_data(config_data)
        with open(config_path + ".sig", "wb") as f:
            f.write(signature)
        print(f"Successfully signed {config_path}. Signature written to {config_path}.sig", file=sys.stdout)
        logger.info(f"Signed config file {config_path} with signature {signature.hex()[:16]}...")
    except Exception as e:
        print(f"Error: Invalid key or configuration: {e}", file=sys.stdout)
        logger.error(f"Failed to sign config file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Sign a UPM configuration file.")
    parser.add_argument("config_file", help="Path to the configuration file to sign")
    parser.add_argument("--private-key-path", required=True, help="Path to the private key file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parser_args()

    sign_config(args.config_file, args.private_key_path, args.verbose)

if __name__ == "__main__":
    main()