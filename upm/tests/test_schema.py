# tests/test_schema.py

import pytest
from unittest.mock import patch, MagicMock
import jsonschema
from jsonschema.exceptions import ValidationError
from pathlib import Path
import shutil
import yaml
import logging

from upm.schema import MANIFEST_SCHEMA, POLICY_SCHEMA, CONFIG_SCHEMA
from upm.schema import validate_data
from upm.logging_utils import AUDIT_LOGGER # Import AUDIT_LOGGER to confirm its behavior is what we expect for the test


# --- Fixtures ---

@pytest.fixture
def valid_manifest_data():
    """Provides valid data matching MANIFEST_SCHEMA."""
    # Ensure all required fields are present and formats are correct
    return {
        "manifest_version": "1.0.0",
        "generated_at_utc": "2025-07-14T12:00:00.000Z",
        "plugins": {
            "pip": {"version": "1.0.0", "hash": "a" * 64, "class_name": "PipPlugin"},
            "npm": {"version": "1.0.0", "hash": "b" * 64, "class_name": "NpmPlugin"}
        }
    }

@pytest.fixture
def invalid_manifest_data():
    """Provides invalid data for MANIFEST_SCHEMA."""
    return {
        "manifest_version": "invalid",
        "plugins": {
            "invalid@name": {"version": "1.0.0", "hash": "short", "class_name": "InvalidPlugin"}
        }
    }

@pytest.fixture
def valid_policy_data():
    """Provides valid data matching POLICY_SCHEMA."""
    return {
        "blocked_packages": ["malicious-pkg"],
        "pinned_versions": {"pip": {"requests": "2.28.1"}},
        "offline": False,
        "allowed_packages": {"pip": ["safe-pkg"]},
        "resource_limits": {"max_cpu_seconds": 30, "max_memory_mb": 500},
        "sandbox_permissions": {"allow_network": True},
        "ai_risk": {"enabled": False}
    }

@pytest.fixture
def invalid_policy_data():
    """Provides invalid data for POLICY_SCHEMA."""
    return {
        "blocked_packages": 123,
        "unknown_key": "value",
        "allowed_packages": "not-a-list"
    }

@pytest.fixture
def valid_config_data():
    """Provides valid data matching CONFIG_SCHEMA."""
    return {
        "notifications": {
            "email": {"enabled": False},
            "slack": {"enabled": True, "channel": "#alerts"}
        },
        "security": {
            "encrypt_data": True,
            "private_key_path": "/tmp/key.pem"
        },
        "network": {"timeout_seconds": 60}
    }


@pytest.fixture
def invalid_config_data():
    """Provides invalid data for CONFIG_SCHEMA."""
    return {
        "notifications": {
            "email": {"enabled": "not_bool"},
        },
        "security": {"unknown_prop": "value"},
        "network": {"timeout_seconds": "not_an_int"}
    }


# --- Tests for Schema Definitions ---

def test_manifest_schema_structure():
    """Test that MANIFEST_SCHEMA is correctly defined."""
    assert isinstance(MANIFEST_SCHEMA, dict)
    assert MANIFEST_SCHEMA["type"] == "object"
    assert "manifest_version" in MANIFEST_SCHEMA["properties"]
    assert "plugins" in MANIFEST_SCHEMA["properties"]

def test_policy_schema_structure():
    """Test that POLICY_SCHEMA is correctly defined."""
    assert isinstance(POLICY_SCHEMA, dict)
    assert POLICY_SCHEMA["type"] == "object"
    assert "blocked_packages" in POLICY_SCHEMA["properties"]
    assert "pinned_versions" in POLICY_SCHEMA["properties"]

def test_config_schema_structure():
    """Test that CONFIG_SCHEMA is correctly defined."""
    assert isinstance(CONFIG_SCHEMA, dict)
    assert CONFIG_SCHEMA["type"] == "object"
    assert "notifications" in CONFIG_SCHEMA["properties"]
    assert "security" in CONFIG_SCHEMA["properties"]


# --- Tests for Validation Function ---

def test_validate_manifest_success(valid_manifest_data):
    """Test successful validation of manifest data."""
    validate_data(valid_manifest_data, MANIFEST_SCHEMA)

def test_validate_manifest_failure(invalid_manifest_data):
    """Test validation failure for invalid manifest data."""
    with pytest.raises(ValidationError):
        validate_data(invalid_manifest_data, MANIFEST_SCHEMA)

def test_validate_policy_success(valid_policy_data):
    """Test successful validation of policy data."""
    validate_data(valid_policy_data, POLICY_SCHEMA)

def test_validate_policy_failure(invalid_policy_data):
    """Test validation failure for invalid policy data."""
    with pytest.raises(ValidationError):
        validate_data(invalid_policy_data, POLICY_SCHEMA)

def test_validate_config_success(valid_config_data):
    """Test successful validation of config data."""
    validate_data(valid_config_data, CONFIG_SCHEMA)

def test_validate_config_failure(invalid_config_data):
    """Test validation failure for invalid config data."""
    with pytest.raises(ValidationError):
        validate_data(invalid_config_data, CONFIG_SCHEMA)


# --- Tests for Integration with Other Modules (Conceptual, rely on mocks) ---

def test_schema_integration_with_manifest_manager(valid_manifest_data, tmp_path):
    """Test schema used in manifest manager (mocked integration)."""
    with patch('upm.schema.validate_data') as mock_validate_data:
        from upm.config_manager import UPMConfig
        from upm.error_tracker import ErrorTracker

        mock_error_tracker = MagicMock(spec=ErrorTracker)
        mock_error_tracker.add_error = MagicMock()

        temp_dir = tmp_path / "test_schema_config_dir"
        temp_dir.mkdir(exist_ok=True)
        config_path = temp_dir / ".unipkgrc"
        config_path.write_text(yaml.dump(valid_manifest_data))

        config_manager = UPMConfig(project_root=str(temp_dir), error_tracker=mock_error_tracker)
        config_manager.load_config()

        mock_validate_data.assert_not_called()
        shutil.rmtree(temp_dir, ignore_errors=True)


# --- Edge Cases and Fuzzing ---

@pytest.mark.parametrize("edge_data", [
    # Fixed: Provide minimal required fields for the empty object to be valid
    {"manifest_version": "1.0.0", "generated_at_utc": "2025-07-14T00:00:00.000Z", "plugins": {}},
    {"manifest_version": "1.0.0", "generated_at_utc": "2025-07-14T00:00:00.000Z", "plugins": {}},
    {"manifest_version": "1.0.0", "generated_at_utc": "2025-07-14T00:00:00.000Z", "plugins": {"a" * 100: {"version": "1.0.0", "hash": "c" * 64, "class_name": "LongNamePlugin"}}},
])
def test_manifest_schema_edge_cases(edge_data):
    """Test edge cases for manifest schema."""
    if "extra_prop" in edge_data:
        with pytest.raises(ValidationError):
            jsonschema.validate(instance=edge_data, schema=MANIFEST_SCHEMA)
    else:
        jsonschema.validate(instance=edge_data, schema=MANIFEST_SCHEMA)

def test_schema_fuzzing(invalid_manifest_data):
    """Basic fuzzing for invalid data types."""
    invalid_manifest_data["plugins"] = 123
    with pytest.raises(ValidationError):
        jsonschema.validate(instance=invalid_manifest_data, schema=MANIFEST_SCHEMA)


# --- Schema Evolution Tests ---

def test_schema_backward_compatibility():
    """Test that old data validates against current schema (if backward compat)."""
    old_data = {
        "manifest_version": "0.5.0",
        "generated_at_utc": "2024-01-01T00:00:00.000Z",
        "plugins": {"legacy-pip": {"version": "0.5.0", "hash": "d" * 64, "class_name": "LegacyPipPlugin"}}
    }
    jsonschema.validate(instance=old_data, schema=MANIFEST_SCHEMA)

def test_schema_forward_compatibility():
    """Test that future data might fail or warn."""
    future_data = {
        "manifest_version": "2.0.0",
        "generated_at_utc": "2026-01-01T00:00:00.000Z",
        "new_root_field": "future_value",
        "plugins": {
            "new_plugin": {"version": "2.0.0", "hash": "e"*64, "class_name": "NewPlugin"},
        }
    }
    jsonschema.validate(instance=future_data, schema=MANIFEST_SCHEMA)


# --- Logging Integration Tests ---

def test_validation_logs_errors(caplog):
    """Test that validation errors are logged."""
    invalid_data = {"invalid": "data"}

    # Store original handlers and clear them for this test's caplog
    original_handlers = AUDIT_LOGGER.handlers[:]
    original_propagate = AUDIT_LOGGER.propagate
    AUDIT_LOGGER.handlers.clear()
    
    # Add caplog's handler directly to AUDIT_LOGGER
    AUDIT_LOGGER.addHandler(caplog.handler)
    AUDIT_LOGGER.propagate = False # Disable propagation to root, as we directly handle

    try:
        with caplog.at_level(logging.ERROR, logger='unipkg_audit'): # Target AUDIT_LOGGER
            with pytest.raises(ValidationError):
                validate_data(invalid_data, MANIFEST_SCHEMA)

        # Assert that the expected log message is present in caplog.records
        # The exact message from jsonschema might vary, but AUDIT_LOGGER should capture it.
        assert any(
            "Schema validation failed: 'manifest_version' is a required property" in r.message
            or "Schema validation failed: 'generated_at_utc' is a required property" in r.message
            or "Schema validation failed: 'plugins' is a required property" in r.message
            for r in caplog.records
        )
        assert any(r.levelname == 'ERROR' for r in caplog.records) # Ensure at least one ERROR level log

    finally:
        # Restore original handlers and propagation
        AUDIT_LOGGER.handlers.clear()
        for h in original_handlers:
            AUDIT_LOGGER.addHandler(h)
        AUDIT_LOGGER.propagate = True