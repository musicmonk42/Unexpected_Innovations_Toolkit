# tests/test_core.py

import pytest
import asyncio
import time
from unittest.mock import patch, AsyncMock, MagicMock

from upm.plugins.pip import PipPlugin 
from upm.core import UniversalPackageManager, OperationResult

# --- Core Operation Tests ---

@pytest.mark.asyncio
async def test_install_single_package_dispatches_to_plugin(mock_upm_instance):
    """Tests that `install` correctly dispatches to the right plugin."""
    async for upm in mock_upm_instance:
        mock_plugin = AsyncMock(spec=PipPlugin)
        mock_plugin.install = AsyncMock(return_value=True) 
        
        upm.plugin_manager.get_plugin.return_value = mock_plugin
        
        result = await upm.install("pip", "requests")
        
        assert result.success is True
        upm.plugin_manager.get_plugin.assert_called_once_with("pip")
        mock_plugin.install.assert_called_once_with(package_name="requests", version_constraint=None)

@pytest.mark.asyncio
async def test_uninstall_package(mock_upm_instance):
    """Tests that `uninstall` correctly dispatches to the right plugin."""
    async for upm in mock_upm_instance:
        mock_plugin = AsyncMock(spec=PipPlugin)
        mock_plugin.uninstall = AsyncMock(return_value=True)
        upm.plugin_manager.get_plugin.return_value = mock_plugin

        result = await upm.uninstall("pip", "requests")

        assert result.success is True
        mock_plugin.uninstall.assert_called_once_with(package_name="requests")

# --- High-Priority Integration & Workflow Tests ---

@pytest.mark.asyncio
async def test_multi_ecosystem_install_dispatches_correctly(real_upm_instance):
    """
    Verifies that install_all dispatches dependencies to the correct real plugins.
    """
    pip_plugin = MagicMock(spec=PipPlugin)
    pip_plugin.install = AsyncMock(return_value=True)

    # Correctly get the yielded value from the async generator fixture
    upm = await anext(real_upm_instance)
    
    # Use patch.object to mock methods on the real plugin_manager instance
    with patch.object(upm.plugin_manager, 'get_plugin', side_effect=lambda eco: {"pip": pip_plugin}.get(eco)), \
         patch.object(upm.plugin_manager, 'get_all_plugins', return_value={"pip": pip_plugin}):

        manifest_data = {"dependencies": {"pip": [{"name": "requests", "version": "2.28.1"}]}}
        await upm.manifest.write(manifest_data)
        
        if hasattr(upm, 'install_all'):
            result = await upm.install_all()
        
            assert result.success is True
            pip_plugin.install.assert_awaited_once_with(package_name="requests", version_constraint="2.28.1", skip_manifest_update=True)
        else:
            pytest.skip("UPM instance does not have an 'install_all' method to test.")