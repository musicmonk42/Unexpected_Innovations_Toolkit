#!/bin/bash

# --- Script: generate_sbom.sh ---
#
# Description:
#   Generates a CycloneDX Software Bill of Materials (SBOM) for the project.
#   It automatically includes both runtime and development dependencies.
#   After generation, it creates a SHA256 hash for integrity checking and can
#   optionally create a GPG signature for authenticity verification.
#
# Security:
#   This script is a critical part of the software supply chain.
#   - It ensures all dependencies are documented.
#   - The generated hash and signature files allow downstream users and automated
#     systems to verify that the SBOM is authentic and has not been tampered with.
#   - It should be run as part of a secure CI/CD pipeline.

# Exit immediately on error, treat unset variables as an error, and fail on pipeline errors.
set -euo pipefail

# --- Configuration ---
OUTPUT_FILE="sbom.json"
REQUIREMENTS_FILE="requirements.txt"
DEV_REQUIREMENTS_FILES=("dev-requirements.txt" "requirements-dev.txt")
GPG_KEY_ID=""

# --- Helper Functions ---
print_usage() {
    echo "Usage: $0 [--sign GPG_KEY_ID] [--help]"
    echo "  Generates and optionally signs a CycloneDX SBOM from requirements files."
    echo
    echo "Options:"
    echo "  --sign GPG_KEY_ID    Cryptographically sign the generated SBOM using the specified GPG key."
    echo "  --help               Display this help message."
}

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --sign)
            # Check if the next argument exists and is not another flag
            if [[ -n "${2-}" && ! "$2" == --* ]]; then
                GPG_KEY_ID="$2"
                shift
            else
                echo "Error: --sign flag requires a GPG Key ID." >&2
                exit 1
            fi
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown parameter passed: $1" >&2
            print_usage
            exit 1
            ;;
    esac
    shift
done

# --- Prerequisite Checks ---
echo "--- Checking for required tools... ---"
if ! command -v cyclonedx-py &> /dev/null; then
    echo "Error: cyclonedx-py is not installed." >&2
    echo "Please install it by running: pip install cyclonedx-py" >&2
    exit 1
fi
echo "✅ cyclonedx-py is found."

if [[ -n "$GPG_KEY_ID" ]]; then
    if ! command -v gpg &> /dev/null; then
        echo "Error: --sign flag was used, but gpg (GnuPG) is not installed." >&2
        exit 1
    fi
    echo "✅ gpg is found."
    # Check if the specified GPG key exists before proceeding.
    if ! gpg --list-secret-keys "$GPG_KEY_ID" &>/dev/null; then
        echo "Error: GPG key '$GPG_KEY_ID' not found in your keyring." >&2
        exit 1
    fi
    echo "✅ GPG key '$GPG_KEY_ID' found."
fi

# --- Pre-run Checks ---
echo -e "\n--- Checking for existing files... ---"
for f in "$OUTPUT_FILE" "$OUTPUT_FILE.sha256" "$OUTPUT_FILE.asc"; do
    if [ -f "$f" ]; then
        echo "Warning: $f already exists and will be overwritten."
    fi
done

# --- SBOM Generation ---
echo -e "\n--- Generating SBOM... ---"

input_files_args=()
if [ -f "$REQUIREMENTS_FILE" ]; then
    echo "Found runtime dependencies file: $REQUIREMENTS_FILE"
    input_files_args+=("-i" "$REQUIREMENTS_FILE")
else
    echo "Warning: $REQUIREMENTS_FILE not found. SBOM may be incomplete."
fi

for dev_file in "${DEV_REQUIREMENTS_FILES[@]}"; do
    if [ -f "$dev_file" ]; then
        echo "Found development dependencies file: $dev_file"
        input_files_args+=("-i" "$dev_file")
    fi
done

if [ ${#input_files_args[@]} -eq 0 ]; then
    echo "Error: No dependency files found. Cannot generate SBOM." >&2
    exit 1
fi

echo "Running cyclonedx-py to generate $OUTPUT_FILE..."
cyclonedx-py --pip "${input_files_args[@]}" --output-format json -o "$OUTPUT_FILE"

echo "✅ SBOM generated successfully: $OUTPUT_FILE"

# --- Hashing and Signing for Integrity ---
echo -e "\n--- Creating Integrity and Authenticity Files... ---"

# 1. Generate SHA256 Hash
echo "Generating SHA256 hash for $OUTPUT_FILE..."
HASH_CMD=""
if command -v sha256sum &> /dev/null; then
    HASH_CMD="sha256sum"
else
    HASH_CMD="shasum -a 256"
fi
$HASH_CMD "$OUTPUT_FILE" > "$OUTPUT_FILE.sha256"
echo "✅ SHA256 hash created: $OUTPUT_FILE.sha256"

# 2. Generate GPG Signature (if requested)
if [[ -n "$GPG_KEY_ID" ]]; then
    echo "Signing $OUTPUT_FILE with GPG key '$GPG_KEY_ID'..."
    gpg --armor --batch --yes --detach-sign --local-user "$GPG_KEY_ID" -o "$OUTPUT_FILE.asc" "$OUTPUT_FILE"
    echo "✅ GPG signature created: $OUTPUT_FILE.asc"
fi

# --- Verification Instructions ---
echo -e "\n--------------------------------------------------"
echo "✅ SBOM Generation Complete!"
echo "--------------------------------------------------"
echo
echo "IMPORTANT: Please add the following verification instructions to your project's README.md"
echo "to allow users and security teams to verify the integrity and authenticity of the SBOM."
echo
echo '```markdown'
echo "### Verifying the SBOM"
echo
echo "The Software Bill of Materials (SBOM) is provided in CycloneDX format (\`$OUTPUT_FILE\`)."
echo "To ensure its integrity and authenticity, you can verify its hash and GPG signature."
echo
echo "**1. Verify the SHA256 Hash:**"
echo
echo "   This ensures the file has not been altered."
echo
echo "   \`\`\`sh"
echo "   # On Linux"
echo "   sha256sum -c $OUTPUT_FILE.sha256"
echo
echo "   # On macOS"
echo "   shasum -a 256 -c $OUTPUT_FILE.sha256"
echo "   \`\`\`"
echo
if [[ -n "$GPG_KEY_ID" ]]; then
    echo "**2. Verify the GPG Signature:**"
    echo
    echo "   This proves the SBOM was generated by a trusted source."
    echo "   First, import the project's public GPG key (key ID: $GPG_KEY_ID)."
    echo
    echo "   \`\`\`sh"
    echo "   gpg --recv-keys $GPG_KEY_ID"
    echo "   gpg --verify $OUTPUT_FILE.asc $OUTPUT_FILE"
    echo "   \`\`\`"
    echo
    echo "The output should indicate a 'Good signature' from the trusted publisher."
fi
echo '```'
echo