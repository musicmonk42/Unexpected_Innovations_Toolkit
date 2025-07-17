# scripts/sign_config.py

import sys
import os
import argparse
import asyncio
from typing import Optional

# Add the parent directory of 'upm' to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
# Go up two levels from scripts/ to the project root
upm_root_dir = os.path.abspath(os.path.join(script_dir, '..'))
sys.path.insert(0, upm_root_dir)


try:
    from upm.core import UniversalPackageManager
    from upm.logging_utils import configure_logging, AUDIT_LOGGER
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError as e:
    print(f"Error: Could not import UPM components. Ensure '{upm_root_dir}' is in your Python path. Details: {e}", file=sys.stderr)
    sys.exit(1)

async def async_main():
    """
    Asynchronous main function to handle the core logic.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Sign a UPM configuration file with a private RSA key.\n\n"
            "This script enforces the use of strong cryptography:\n"
            "- RSA keys must be 2048 bits or greater.\n"
            "- The signing process uses RSA-PSS with a SHA-256 hash function.\n\n"
            "For enterprise-grade security, the generated signature (.sig) file should be\n"
            "distributed securely or registered in a tamper-evident system."
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "config_file",
        help="Path to the configuration file to sign (e.g., .unipkgrc)."
    )
    parser.add_argument(
        "--private-key-path",
        required=True,
        help="Path to the RSA private key file (.pem format) for signing."
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Optional: Path to save the signature file. Defaults to <config_file>.sig."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output."
    )

    args = parser.parse_args()
    configure_logging(verbose=args.verbose)
    if args.verbose:
        print("Verbose mode enabled.")

    try:
        # --- File and Key Validation ---
        if not os.path.exists(args.config_file):
            print(f"Error: Config file not found at {args.config_file}")
            sys.exit(1)
        if not os.path.exists(args.private_key_path):
            print(f"Error: Private key file not found at {args.private_key_path}")
            sys.exit(1)

        print(f"Loading private key from: {args.private_key_path}")
        with open(args.private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
            print("Error: Invalid or insecure key. Must be an RSA private key of at least 2048 bits.")
            sys.exit(1)

        # --- UPM Instantiation and Signing ---
        print("Attempting to sign configuration file...")
        signature_output_path = args.output or f"{args.config_file}.sig"
        
        # Instantiate UniversalPackageManager using its async factory method.
        # The project root is the directory containing the config file.
        project_root = os.path.dirname(os.path.abspath(args.config_file)) or "."
        upm = await UniversalPackageManager.create(project_root=project_root)
        
        # FIX: Manually enable signing for this specific operation, overriding the loaded config.
        upm.encryption_manager.config['require_signatures'] = True

        # Await the asynchronous sign_config method.
        success = await upm.sign_config(args.config_file, private_key, signature_output_path)
        
        if not success:
            print("Failed to sign configuration file. Check logs for details.")
            sys.exit(1)

        print(f"\nSuccessfully signed '{args.config_file}'.")
        print(f"Signature saved to: {signature_output_path}")
        AUDIT_LOGGER.info(f"Signed config file: {args.config_file}", extra={"signature_path": signature_output_path})

    except FileNotFoundError as e:
        print(f"\nError: File not found: {e}", file=sys.stderr)
        AUDIT_LOGGER.error(f"Config signing failed - file not found: {e}", exc_info=True)
        sys.exit(1)
    except (ValueError, TypeError) as e:
        # Catch errors from key loading or other value issues.
        print(f"\nError: Invalid key or configuration: {e}", file=sys.stderr)
        AUDIT_LOGGER.error(f"Config signing failed - invalid key: {e}", exc_info=True)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        AUDIT_LOGGER.critical(f"Unexpected error during config signing: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(async_main())