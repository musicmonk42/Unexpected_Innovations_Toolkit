# upm/schema.py
import json
from typing import Any, Dict # ADDED: Import Any and Dict
from upm.logging_utils import AUDIT_LOGGER # ADDED: Import AUDIT_LOGGER

# Conditional import for jsonschema for validation
try:
    from jsonschema import validate, ValidationError
    _JSONSCHEMA_AVAILABLE = True
except ImportError:
    validate = None
    ValidationError = type('ValidationError', (Exception,), {}) # Dummy class
    _JSONSCHEMA_AVAILABLE = False


def validate_payload(payload):
    # Placeholder for actual validation logic, e.g., using jsonschema or pydantic
    data = json.loads(payload)
    if "manifest" not in data:
        raise ValueError("Payload missing 'manifest' key.")
    # Additional validation can be added here
    pass

# --- JSON Schema Definitions for UPM entities ---
# These schemas are designed to be used with jsonschema for validation.

# Manifest Schema (unipkg.yaml / plugin_manifest.json)
MANIFEST_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "UPM Manifest Schema",
    "description": "Schema for unipkg.yaml and plugin_manifest.json files.",
    "type": "object",
    "required": ["manifest_version", "generated_at_utc", "plugins"],
    "properties": {
        "manifest_version": {
            "type": "string",
            "pattern": "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|[a-zA-Z-][a-zA-Z0-9-]*)(?:\\.(?:0|[1-9]\\d*|[a-zA-Z-][a-zA-Z0-9-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$"
        },
        "generated_at_utc": {
            "type": "string",
            "format": "date-time"
        },
        "plugins": {
            "type": "object",
            "patternProperties": {
                "^[a-zA-Z0-9_.-]+$": { # Regex for plugin/ecosystem name
                    "type": "object",
                    "required": ["version", "hash", "class_name"],
                    "properties": {
                        "version": {"type": "string"},
                        "hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}, # SHA256 hash
                        "class_name": {"type": "string"},
                        "signature": {"type": "string"}, # Optional GPG/digital signature
                        "metadata": {"type": "object"} # Additional metadata
                    },
                    "additionalProperties": True
                }
            },
            "additionalProperties": False
        }
    },
    "additionalProperties": True
}

# Policy Schema (.unipkgpolicy.yaml)
POLICY_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "UPM Policy Schema",
    "description": "Schema for .unipkgpolicy.yaml files.",
    "type": "object",
    "properties": {
        "blocked_packages": {
            "type": "array",
            "items": {"type": "string", "pattern": "^(@[a-z0-9-~][a-z0-9-._~]*\\/)?[a-z0-9-~][a-z0-9-._~]*$"} # Package name regex
        },
        "allowed_packages": {
            "type": "object",
            "patternProperties": {
                "^[a-z]+$": { # Ecosystem name regex (e.g., pip, npm)
                    "type": "array",
                    "items": {"type": "string", "pattern": "^(@[a-z0-9-~][a-z0-9-._~]*\\/)?[a-z0-9-~][a-z0-9-._~]*$"}
                }
            },
            "additionalProperties": False
        },
        "pinned_versions": {
            "type": "object",
            "patternProperties": {
                "^[a-z]+$": { # Ecosystem name regex
                    "type": "object",
                    "patternProperties": {
                        "^[a-zA-Z0-9_.-]+$": {"type": "string"} # Package name: version constraint
                    },
                    "additionalProperties": False
                }
            },
            "additionalProperties": False
        },
        "offline": {"type": "boolean"},
        "disallow_install_scripts": {"type": "boolean"},
        "resource_limits": { # For isolated plugins
            "type": "object",
            "properties": {
                "max_cpu_seconds": {"type": ["integer", "number"]},
                "max_memory_mb": {"type": ["integer", "number"]}
            },
            "additionalProperties": True
        },
        "sandbox_permissions": { # For seccomp rules
            "type": "object",
            "properties": {
                "allow_network": {"type": "boolean"},
                "allow_write": {"type": "boolean"},
                "allow_exec": {"type": "boolean"}
            },
            "additionalProperties": True
        },
        "ai_risk": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "model_path": {"type": "string"},
                "cache_dir": {"type": "string"},
                "verbose": {"type": "boolean"}
            },
            "additionalProperties": True
        }
    },
    "additionalProperties": True
}

# General Configuration Schema (.unipkgrc)
CONFIG_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "UPM Configuration Schema",
    "description": "Schema for .unipkgrc configuration file.",
    "type": "object",
    "properties": {
        "notifications": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "sender": {"type": "string", "format": "email"},
                        "recipient": {"type": "string", "format": "email"},
                        "smtp_server": {"type": "string"},
                        "smtp_port": {"type": "integer"},
                        "email_password": {"type": "string"} # Resolved from env var
                    },
                    "additionalProperties": True
                },
                "slack": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "webhook_url": {"type": "string", "format": "uri"},
                        "channel": {"type": "string", "pattern": "^#(.){1,21}$"}, # Slack channel format
                        "slack_token": {"type": "string"} # Resolved from env var
                    },
                    "additionalProperties": True
                }
            },
            "additionalProperties": True
        },
        "security": {
            "type": "object",
            "properties": {
                "encrypt_data": {"type": "boolean"},
                "require_signatures": {"type": "boolean"},
                "encryption_key_path": {"type": "string"},
                "private_key_path": {"type": "string"},
                "public_key_path": {"type": "string"},
                "api_key": {"type": "string"}, # Resolved from env var
                "plugin_trust_store_path": {"type": "string"}
            },
            "additionalProperties": True
        },
        "network": {
            "type": "object",
            "properties": {
                "timeout_seconds": {"type": "integer", "minimum": 1},
                "proxy": {"type": "string"},
                "verify_ssl": {"type": "boolean"},
                "ca_bundle": {"type": "string"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "disable_retries": {"type": "boolean"}
            },
            "additionalProperties": True
        },
        "search": {
            "type": "object",
            "properties": {
                "cache_ttl_seconds": {"type": "integer", "minimum": 0},
                "per_ecosystem_ttl": {
                    "type": "object",
                    "patternProperties": {
                        "^[a-z]+$": {"type": "integer", "minimum": 0} # Ecosystem name: ttl
                    },
                    "additionalProperties": False
                },
                "concurrency_limit": {"type": "integer", "minimum": 1},
                "per_plugin_timeout_seconds": {"type": "integer", "minimum": 1}
            },
            "additionalProperties": True
        },
        "ai": { # AI risk assessment configuration
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "model_path": {"type": "string"},
                "cache_dir": {"type": "string"},
                "verbose": {"type": "boolean"}
            },
            "additionalProperties": True
        }
    },
    "additionalProperties": True
}


def validate_data(instance: Any, schema: Dict[str, Any]) -> None:
    """Validates data against a given JSON schema."""
    if not _JSONSCHEMA_AVAILABLE:
        # Log a warning or raise a specific error if validation cannot occur.
        raise ImportError("jsonschema library is required for validation but not installed.")
    
    try:
        validate(instance=instance, schema=schema)
    except ValidationError as e:
        # Log the validation error
        AUDIT_LOGGER.error(f"Schema validation failed: {e.message} at path {'/'.join(map(str, e.path))}", exc_info=False)
        raise # Re-raise the original ValidationError as the test expects it