# tests/test_rust_bridge.py

import pytest
import json
from unittest.mock import patch, MagicMock
import asyncio  # If needed for async tests
import time # For performance tests
import os # For checking if the module exists

# Conditional import for the Rust module via pyo3
# This block attempts to import the module and sets a flag.
try:
    import upm_resolver_rs
    _RUST_RESOLVER_AVAILABLE = True
except ImportError:
    upm_resolver_rs = None
    _RUST_RESOLVER_AVAILABLE = False
    print("Warning: 'upm_resolver_rs' not found. Skipping Rust bridge tests.")

# --- Fixtures ---

@pytest.fixture
def sample_manifest():
    """Provides a sample UPM manifest for testing."""
    return json.dumps({
        "dependencies": {
            "python": [{"name": "numpy", "version": ">=1.0.0", "ecosystem": "python"}]
        }
    })

@pytest.fixture
def sample_policies():
    """Provides sample policies for testing."""
    return json.dumps({
        "blocked_packages": []
    })

# Decorator to skip all tests in this file if the Rust resolver is not available
@pytest.mark.skipif(not _RUST_RESOLVER_AVAILABLE, reason="Rust resolver 'upm_resolver_rs' is not built or not in PYTHONPATH.")
class TestRustBridge:
    # Use the imported resolve_deps directly in tests
    # Access it as upm_resolver_rs.resolve_deps

    def test_resolve_deps_success(self, sample_manifest, sample_policies):
        """Test successful dependency resolution."""
        # Mock the Rust `resolve_deps` function's behavior for controlled testing.
        with patch('upm_resolver_rs.resolve_deps', return_value=json.dumps({"python": [{"name": "numpy", "version": "1.24.0"}]})) as mock_rust_resolve_deps:
            # We call the function using the module reference.
            result_str = upm_resolver_rs.resolve_deps(sample_manifest, sample_policies, offline_mode=False, cache_dir="/tmp/cache")
            result = json.loads(result_str)
            assert "python" in result
            assert len(result["python"]) > 0
            assert result["python"][0]["name"] == "numpy"
            mock_rust_resolve_deps.assert_called_once_with(sample_manifest, sample_policies, False, "/tmp/cache")


    def test_resolve_deps_offline_mode(self, sample_manifest, sample_policies):
        """Test resolution in offline mode (cache-dependent)."""
        with patch('upm_resolver_rs.resolve_deps', side_effect=ValueError("Offline mode resolution failed: cache miss")) as mock_rust_resolve_deps:
            with pytest.raises(ValueError, match="Offline mode resolution failed: cache miss"):
                upm_resolver_rs.resolve_deps(sample_manifest, sample_policies, offline_mode=True, cache_dir="/non_existent/cache")
            mock_rust_resolve_deps.assert_called_once_with(sample_manifest, sample_policies, True, "/non_existent/cache")


    def test_resolve_deps_version_conflict(self, sample_manifest, sample_policies):
        """Test handling of version conflicts."""
        conflict_manifest = json.dumps({
            "dependencies": {
                "python": [
                    {"name": "pkgA", "version": "1.0"},
                    {"name": "pkgA", "version": "2.0"}
                ]
            }
        })
        with patch('upm_resolver_rs.resolve_deps', side_effect=ValueError("Conflicts found: pkgA versions 1.0 and 2.0")) as mock_rust_resolve_deps:
            with pytest.raises(ValueError, match="Conflicts found"):
                upm_resolver_rs.resolve_deps(conflict_manifest, sample_policies, offline_mode=False, cache_dir="/tmp/cache")
            mock_rust_resolve_deps.assert_called_once_with(conflict_manifest, sample_policies, False, "/tmp/cache")


    def test_resolve_deps_invalid_input(self):
        """Test handling of invalid manifest/policies input."""
        invalid_manifest = "not json"
        with patch('upm_resolver_rs.resolve_deps', side_effect=ValueError("JSON decode error")) as mock_rust_resolve_deps:
            with pytest.raises(ValueError, match="JSON decode"):
                upm_resolver_rs.resolve_deps(invalid_manifest, "{}", offline_mode=False, cache_dir="/tmp/cache")
            mock_rust_resolve_deps.assert_called_once_with(invalid_manifest, "{}", False, "/tmp/cache")


    # --- Tests for Semver Handling ---

    def test_resolve_deps_semver_fallback(self):
        """Test semver parsing and fallback to string equality."""
        manifest = json.dumps({
            "dependencies": {
                "npm": [{"name": "express", "version": "^4.0.0", "ecosystem": "npm"}]
            }
        })
        with patch('upm_resolver_rs.resolve_deps', return_value=json.dumps({"npm": [{"name": "express", "version": "4.20.0"}]})) as mock_rust_resolve_deps:
            result_str = upm_resolver_rs.resolve_deps(manifest, "{}", offline_mode=False, cache_dir="/tmp/cache")
            result = json.loads(result_str)
            
            assert "npm" in result
            assert result["npm"][0]["version"].startswith("4.")
            mock_rust_resolve_deps.assert_called_once_with(manifest, "{}", False, "/tmp/cache")


    # --- Integration Tests with Python Side (Mocked Rust) ---

    @pytest.mark.asyncio
    async def test_rust_bridge_integration_with_core(self, sample_manifest, sample_policies):
        """Test a conceptual integration point where Python code might call the Rust resolver."""
        # This test demonstrates mocking the Rust FFI function and asserting its call.
        # It doesn't test actual `UniversalPackageManager` behavior directly, as `core.py` doesn't
        # directly call `upm_resolver_rs.resolve_deps`. This is for FFI integration verification.
        
        # Mock the actual Rust FFI function
        with patch('upm_resolver_rs.resolve_deps', return_value=json.dumps({"resolved_by_rust": True})) as mock_rust_resolve_deps:
            # Simulate a Python function that would call the Rust resolver
            async def python_wrapper_calling_rust():
                # In a real scenario, this could be a method in a plugin or resolver utility
                return await asyncio.to_thread(
                    upm_resolver_rs.resolve_deps, 
                    sample_manifest, 
                    sample_policies, 
                    False, 
                    "/tmp/cache"
                )

            result = await python_wrapper_calling_rust()
            assert json.loads(result) == {"resolved_by_rust": True}
            mock_rust_resolve_deps.assert_called_once_with(sample_manifest, sample_policies, False, "/tmp/cache")


    # --- Performance and Concurrency Tests (Mocked Rust) ---

    def test_resolve_deps_large_manifest_performance(self):
        """Test performance with large manifest (using mocked Rust resolver)."""
        large_manifest = json.dumps({
            "dependencies": {
                "python": [{"name": f"pkg{i}", "version": "1.0", "ecosystem": "python"} for i in range(100)]
            }
        })
        start_time = time.time()
        with patch('upm_resolver_rs.resolve_deps', return_value=json.dumps({"python": [{"name": f"pkg{i}", "version": "1.0"}] * 100})) as mock_rust_resolve_deps:
            result_str = upm_resolver_rs.resolve_deps(large_manifest, "{}", offline_mode=False, cache_dir="/tmp/cache")
            duration = time.time() - start_time
            assert duration < 1.0  # Arbitrary threshold; this checks Python overhead with mocked Rust
            result = json.loads(result_str)
            assert len(result.get("python", [])) == 100
            mock_rust_resolve_deps.assert_called_once()


    @pytest.mark.asyncio
    async def test_resolve_deps_concurrency(self, sample_manifest, sample_policies):
        """Test concurrent calls to resolve_deps (using mocked Rust resolver)."""
        with patch('upm_resolver_rs.resolve_deps', side_effect=lambda *a, **kw: json.dumps({"resolved": True})) as mock_rust_resolve_deps:
            tasks = [asyncio.to_thread(upm_resolver_rs.resolve_deps, sample_manifest, sample_policies, False, "/tmp/cache") for _ in range(10)]
            results = await asyncio.gather(*tasks)
            assert all(json.loads(r) == {"resolved": True} for r in results)
            assert mock_rust_resolve_deps.call_count == 10


    # --- Error Handling and Fuzzing (Mocked Rust) ---

    def test_resolve_deps_fetch_failure(self):
        """Test handling of fetch errors (simulated from Rust resolver)."""
        manifest = json.dumps({
            "dependencies": {
                "python": [{"name": "non_existent_pkg", "ecosystem": "python"}]
            }
        })
        with patch('upm_resolver_rs.resolve_deps', side_effect=ValueError("Failed to resolve dependency: non_existent_pkg")) as mock_rust_resolve_deps:
            with pytest.raises(ValueError, match="Failed to resolve"):
                upm_resolver_rs.resolve_deps(manifest, "{}", offline_mode=False, cache_dir="/tmp/cache")
            mock_rust_resolve_deps.assert_called_once()


    @pytest.mark.parametrize("fuzz_input", [
        "{{invalid json}}",  # Malformed
        json.dumps({"dependencies": {"python": [{"name": "; rm -rf /", "version": "1.0"}]}}),  # Injection
        json.dumps({"dependencies": {}})  # Empty
    ])
    def test_resolve_deps_fuzzing(self, fuzz_input, sample_policies):
        """Fuzz test for invalid inputs (simulated errors from Rust resolver)."""
        with patch('upm_resolver_rs.resolve_deps', side_effect=ValueError("Simulated Rust error for fuzzed input")) as mock_rust_resolve_deps:
            # Expect either a ValueError from the mock or a JSONDecodeError if Python parsing fails before the call.
            with pytest.raises((ValueError, json.JSONDecodeError)):
                upm_resolver_rs.resolve_deps(fuzz_input, sample_policies, offline_mode=False, cache_dir="/tmp/cache")
            # mock_rust_resolve_deps might not be called if JSONDecodeError occurs earlier
            # So we can't assert call_count reliably here.


    # --- Logging Integration Tests (Mocked Rust) ---

    def test_resolve_deps_logs_errors(self, caplog):
        """Test that resolution errors are logged (simulated from Rust resolver)."""
        invalid_manifest = "bad json"
        with patch('upm_resolver_rs.resolve_deps', side_effect=ValueError("Bad JSON input")) as mock_rust_resolve_deps:
            import logging # Ensure logging is imported
            with caplog.at_level(logging.ERROR): # Capture ERROR level logs
                with pytest.raises(ValueError): # Expected error from resolve_deps
                    upm_resolver_rs.resolve_deps(invalid_manifest, "{}", offline_mode=False, cache_dir="/tmp/cache")
            assert "Bad JSON input" in caplog.text # Check for the specific error message
            mock_rust_resolve_deps.assert_called_once()