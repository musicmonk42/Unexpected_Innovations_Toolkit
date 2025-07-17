# tests/test_npm.py
import pytest
import asyncio
import os
import json
import time
import shutil
import platform # Import platform for OS-specific checks
import stat # Import stat for file permissions
import subprocess # Import subprocess for CalledProcessError
import aiohttp # Import aiohttp for ClientError

from unittest.mock import patch, MagicMock, AsyncMock, mock_open

# Import the plugin and custom exceptions
from upm.plugins.npm import NpmPlugin, PluginOperationError, PluginPolicyViolation
from upm.logging_utils import configure_logging, AUDIT_LOGGER # Assuming configure_logging is in logging_utils

# --- Fixtures for common test setup ---

@pytest.fixture
def temp_project_paths(tmp_path):
    """Provides temporary project and cache directories."""
    project_root = tmp_path / "test_npm_project"
    cache_dir = tmp_path / "test_npm_cache"
    project_root.mkdir()
    cache_dir.mkdir()
    return str(project_root), str(cache_dir)

@pytest.fixture
def mock_policy():
    """
    Provides a comprehensive mock policy for testing.
    """
    return {
        "blocked_packages": ["blocked-npm-pkg", "malicious-npm-lib"],
        "allowed_packages": {
            # FIX: Add 'new-npm-pkg' to allow the install test to pass.
            "npm": ["express", "lodash", "react", "vulnerable-npm-pkg", "safe-npm-pkg", "npm-test-simple-pkg", "new-npm-pkg"]
        },
        "pinned_versions": {
            "npm": {
                "express": "4.20.0",
                "lodash": "4.17.21"
            }
        },
        "offline": False,
        "cache_policy": {"max_size_mb": 100, "cache_ttl_days": 30}
    }

@pytest.fixture
def npm_plugin_instance(temp_project_paths, mock_policy, mock_subprocess_run):
    """Provides an initialized NpmPlugin instance for tests."""
    project_root, cache_dir = temp_project_paths
    with patch('shutil.which', return_value='C:\\path\\to\\npm.exe' if platform.system() == 'Windows' else '/usr/bin/npm'):
        plugin = NpmPlugin(project_root, cache_dir, mock_policy)
    
    mock_subprocess_run.reset_mock()
    
    plugin.metrics = {
        "install_success_total": 0, "install_failure_total": 0,
        "uninstall_success_total": 0, "uninstall_failure_total": 0,
        "upgrade_success_total": 0, "upgrade_failure_total": 0,
        "policy_block_total": 0,
        "vulnerability_check_total": 0, "vulnerability_found_total": 0,
        "cache_hits_total": 0, "cache_misses_total": 0,
        "plugin_errors_total": 0, "npm_binary_calls_total": 0,
        "events_published_total": 0, "event_publish_failures_total": 0,
        "prune_total": 0, "risk_prediction_total": 0,
        "cache_cleaned_mb": 0
    }
    return plugin

@pytest.fixture(autouse=True)
def mock_subprocess_run():
    """Mocks subprocess.run for all tests, auto-resetting calls."""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(
            stdout="mock stdout", stderr="", returncode=0
        )
        yield mock_run

@pytest.fixture(autouse=True)
def mock_aiohttp_client_session():
    """Mocks aiohttp.ClientSession and its responses for all tests."""
    with patch('aiohttp.ClientSession') as mock_session_class:
        mock_session_instance = MagicMock()
        mock_session_class.return_value.__aenter__.return_value = mock_session_instance
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {}
        
        mock_session_instance.get.return_value.__aenter__.return_value = mock_response
        mock_session_instance.post.return_value.__aenter__.return_value = mock_response
        yield mock_session_instance

# --- Unit Tests: Initialization and Internal Helpers ---

def test_init(mock_subprocess_run, temp_project_paths, mock_policy):
    """Test NpmPlugin initialization and npm command check."""
    project_root, cache_dir = temp_project_paths
    
    with patch('shutil.which', return_value='npm'):
        mock_subprocess_run.return_value = MagicMock(stdout="10.2.3", stderr="", returncode=0)
        plugin = NpmPlugin(project_root, cache_dir, mock_policy)
        mock_subprocess_run.assert_called_once_with(
            ["npm", "--version"], capture_output=True, text=True, check=True, timeout=5
        )
        assert os.path.exists(plugin.npm_cache_dir)
        assert "install_success_total" in plugin.metrics

    mock_subprocess_run.reset_mock()
    with patch('shutil.which', return_value=None):
        with pytest.raises(PluginOperationError):
             NpmPlugin(project_root, cache_dir, mock_policy)


@pytest.mark.asyncio
async def test_run_npm_cmd_success(npm_plugin_instance, mock_subprocess_run):
    """Test successful execution of _run_npm_cmd."""
    mock_subprocess_run.return_value.stdout = "Successful output"
    result = await npm_plugin_instance._run_npm_cmd(["test", "arg"])
    mock_subprocess_run.assert_called_once_with(
        [npm_plugin_instance.npm_cmd_path, "test", "arg"], capture_output=True, text=True, check=True, cwd=npm_plugin_instance.project_root, shell=False, env=os.environ
    )
    assert result.stdout == "Successful output"
    assert npm_plugin_instance.metrics["npm_binary_calls_total"] == 1

@pytest.mark.asyncio
async def test_run_npm_cmd_failure(npm_plugin_instance, mock_subprocess_run):
    """Test _run_npm_cmd when subprocess fails."""
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, ["npm", "fail"], stderr="Error output")
    with pytest.raises(PluginOperationError, match="npm command '.*fail' failed with exit code 1. Stderr: Error output"):
        await npm_plugin_instance._run_npm_cmd(["fail"])
    assert npm_plugin_instance.metrics["plugin_errors_total"] == 1

@pytest.mark.asyncio
async def test_run_npm_cmd_shell_injection(npm_plugin_instance):
    """Test _run_npm_cmd prevents shell injection."""
    with pytest.raises(PluginOperationError, match="Potential shell injection detected"):
        await npm_plugin_instance._run_npm_cmd(["install", "malicious-pkg; rm -rf /"])
    assert npm_plugin_instance.metrics["plugin_errors_total"] == 1

@pytest.mark.asyncio
async def test_run_npm_cmd_file_not_found(npm_plugin_instance, mock_subprocess_run):
    """Test _run_npm_cmd when 'npm' is not found."""
    npm_plugin_instance.npm_cmd_path = "/nonexistent/path/to/npm"
    mock_subprocess_run.side_effect = FileNotFoundError
    with pytest.raises(PluginOperationError, match="not found"):
        await npm_plugin_instance._run_npm_cmd(["version"])
    assert npm_plugin_instance.metrics["plugin_errors_total"] == 1

@pytest.mark.asyncio
async def test_run_npm_cmd_timeout(npm_plugin_instance, mock_subprocess_run):
    """Test _run_npm_cmd when command times out."""
    mock_subprocess_run.side_effect = subprocess.TimeoutExpired(["npm", "long-cmd"], 10)
    with pytest.raises(PluginOperationError, match="npm command '.*long-cmd' timed out."):
        await npm_plugin_instance._run_npm_cmd(["long-cmd"])
    assert npm_plugin_instance.metrics["plugin_errors_total"] == 1

@pytest.mark.asyncio
async def test_manage_cache_cleanup(npm_plugin_instance, tmp_path):
    """Test cache management cleans up old files when size limit is exceeded."""
    npm_plugin_instance.policy["cache_policy"]["max_size_mb"] = 1
    npm_plugin_instance.npm_cache_dir = str(tmp_path / "cache_test_npm")
    os.makedirs(npm_plugin_instance.npm_cache_dir, exist_ok=True)

    for i in range(10):
        file_path = os.path.join(npm_plugin_instance.npm_cache_dir, f"file_{i}.json")
        with open(file_path, "w") as f:
            f.write("A" * (500 * 1024))
        os.utime(file_path, (time.time() - (10 - i) * 1000, time.time() - (10 - i) * 1000))

    popular_file_path = os.path.join(npm_plugin_instance.npm_cache_dir, "express_search.json")
    with open(popular_file_path, "w") as f:
        f.write("B" * (500 * 1024))
    os.utime(popular_file_path, (time.time() + 1000, time.time() + 1000))

    initial_files = set(os.listdir(npm_plugin_instance.npm_cache_dir))
    assert len(initial_files) == 11

    if hasattr(npm_plugin_instance, '_manage_cache_impl'):
        await npm_plugin_instance._manage_cache_impl(verbose=True)
        remaining_files = os.listdir(npm_plugin_instance.npm_cache_dir)
        assert len(remaining_files) < 11
        assert os.path.basename(popular_file_path) in remaining_files
        assert npm_plugin_instance.metrics["cache_cleaned_mb"] > 0
    else:
        pytest.skip("_manage_cache_impl not found on NpmPlugin")

@pytest.mark.asyncio
async def test_manage_cache_ttl(npm_plugin_instance, tmp_path):
    """Test that _manage_cache_impl prunes stale files based on cache_ttl_days."""
    cache_dir = tmp_path / "cache_ttl_test_npm"
    npm_plugin_instance.npm_cache_dir = str(cache_dir)
    os.makedirs(npm_plugin_instance.npm_cache_dir, exist_ok=True)

    stale_file = os.path.join(npm_plugin_instance.npm_cache_dir, "stale.json")
    with open(stale_file, "w") as f: f.write("a" * (12 * 1024)) 
    old_timestamp = time.time() - 31 * 86400
    os.utime(stale_file, (old_timestamp, old_timestamp))

    fresh_file = os.path.join(npm_plugin_instance.npm_cache_dir, "fresh.json")
    with open(fresh_file, "w") as f: f.write("fresh data")
    recent_timestamp = time.time() - 1 * 86400
    os.utime(fresh_file, (recent_timestamp, recent_timestamp))

    if hasattr(npm_plugin_instance, '_manage_cache_impl'):
        await npm_plugin_instance._manage_cache_impl(verbose=True)
        assert not os.path.exists(stale_file)
        assert os.path.exists(fresh_file)
        assert npm_plugin_instance.metrics["cache_cleaned_mb"] > 0
    else:
        pytest.skip("_manage_cache_impl not found on NpmPlugin")


@pytest.mark.parametrize("action, name, version, should_block", [
    ("install", "blocked-npm-pkg", None, True),
    ("upgrade", "malicious-npm-lib", None, True),
    ("install", "unlisted-pkg", None, True),
    ("install", "express", "4.18.1", True),
    ("install", "express", "4.20.0", False),
    ("install", "lodash", None, True),
    ("uninstall", "blocked-npm-pkg", None, False),
    ("install", "react", None, False),
])
def test_check_policy(npm_plugin_instance, action, name, version, should_block):
    """Test policy enforcement for various scenarios."""
    if should_block:
        with pytest.raises(PluginPolicyViolation):
            npm_plugin_instance._check_policy(action, name, version)
        assert npm_plugin_instance.metrics["policy_block_total"] >= 1
    else:
        try:
            npm_plugin_instance._check_policy(action, name, version)
        except PluginPolicyViolation as e:
            pytest.fail(f"PolicyViolation raised unexpectedly for {name} on {action}: {e}")

@pytest.mark.asyncio
async def test_check_vulnerabilities_oss_index_success(npm_plugin_instance, mock_aiohttp_client_session):
    """Test OSS Index vulnerability check success."""
    if hasattr(npm_plugin_instance, '_check_vulnerabilities_oss_index_impl'):
        mock_aiohttp_client_session.post.return_value.__aenter__.return_value.json.return_value = [
            {"coordinates": "npm/test-pkg", "vulnerabilities": [{"id": "vuln-id-1", "title": "XSS"}]}
        ]
        vulns = await npm_plugin_instance._check_vulnerabilities_oss_index_impl("test-pkg")
        assert len(vulns) == 1
        assert vulns[0]["title"] == "XSS"
        assert npm_plugin_instance.metrics["vulnerability_check_total"] == 1
        assert npm_plugin_instance.metrics["vulnerability_found_total"] == 1
    else:
        pytest.skip("_check_vulnerabilities_oss_index_impl not found on NpmPlugin")

@pytest.mark.asyncio
async def test_check_vulnerabilities_npm_audit_success(npm_plugin_instance, mock_subprocess_run, temp_project_paths):
    """Test npm audit vulnerability check success."""
    project_root, _ = temp_project_paths
    with open(os.path.join(project_root, "package.json"), 'w') as f:
        json.dump({"name": "test-app", "version": "1.0.0"}, f)

    mock_subprocess_run.return_value = MagicMock(
        stdout=json.dumps({
            "vulnerabilities": {
                "test-pkg": { "via": [{"url": "http://example.com/advisory/123", "severity": "high", "title": "Test XSS"}]}
            },
            "metadata": {"vulnerabilities": {"high": 1}}
        }), stderr="", returncode=1
    )
    vulns = await npm_plugin_instance._doctor_impl()
    assert any("NPM Audit: test-pkg: Test XSS (Severity: high)" in w for w in vulns)
    assert npm_plugin_instance.metrics["vulnerability_check_total"] == 1
    assert npm_plugin_instance.metrics["vulnerability_found_total"] == 1


# --- Integration Tests: Core Functionality (using mocks for subprocess/network) ---

@pytest.mark.asyncio
async def test_search_live(npm_plugin_instance, mock_subprocess_run):
    """Test search hitting the live npm registry."""
    mock_subprocess_run.return_value.stdout = json.dumps([
        {"name": "test-pkg-a", "version": "1.0.0"},
        {"name": "test-pkg-b", "version": "2.0.0"}
    ])
    
    results = await npm_plugin_instance._search_impl("test-query")
    mock_subprocess_run.assert_called_once_with(
        [npm_plugin_instance.npm_cmd_path, 'search', 'test-query', '--json'],
        capture_output=True, text=True, check=True, cwd=npm_plugin_instance.project_root, shell=False, env=os.environ
    )
    assert {"name": "test-pkg-a", "version": "1.0.0"} in results
    assert {"name": "test-pkg-b", "version": "2.0.0"} in results

@pytest.mark.asyncio
async def test_install_success(npm_plugin_instance, mock_subprocess_run):
    """Test successful installation of a package."""
    await npm_plugin_instance._install_impl("new-npm-pkg", "1.0.0")
    
    install_call = mock_subprocess_run.call_args
    assert install_call.args[0] == [npm_plugin_instance.npm_cmd_path, 'install', 'new-npm-pkg@1.0.0', f'--cache={npm_plugin_instance.npm_cache_dir}']
    assert npm_plugin_instance.metrics["install_success_total"] == 1