import pytest
import asyncio
import time
import json

from upm.search_util import SearchUtil, SearchResult, PluginSearchError

@pytest.fixture
def basic_plugin():
    # Always returns a valid result
    class BasicPlugin:
        async def search(self, **kwargs):
            return [
                {"name": "foo", "version": "1.0", "description": "Foo pkg"},
                {"name": "bar", "version": "2.0"},
            ]
    return BasicPlugin()

@pytest.fixture
def plugin_manager(basic_plugin):
    class PMgr:
        def get_plugin(self, eco): return basic_plugin if eco == "py" else None
        def get_all_plugins(self): return {"py": basic_plugin}
    return PMgr()

@pytest.fixture
def search_util(plugin_manager):
    # 1s cache TTL for tests
    return SearchUtil(plugin_manager, network_util=None, config={"search": {"cache_ttl_seconds": 1}})

@pytest.mark.asyncio
async def test_search_returns_normalized(search_util):
    results = await search_util.search("py", "anyquery")
    assert len(results) == 2
    assert all(isinstance(r, SearchResult) for r in results)
    assert results[0].name == "foo"
    assert results[1].version == "2.0"

@pytest.mark.asyncio
async def test_search_cache_behavior(search_util):
    await search_util.search("py", "x")
    # Monkeypatch plugin to never return if called again
    search_util.plugin_manager.get_plugin("py").search = lambda **_: pytest.fail("Should not be called")
    results2 = await search_util.search("py", "x")
    assert len(results2) == 2

@pytest.mark.asyncio
async def test_cache_expiry(search_util):
    await search_util.search("py", "q")
    time.sleep(1.1)
    # Now plugin can be called again (cache expired)
    called = {"flag": False}
    async def search(**_): called["flag"] = True; return [{"name":"a","version":"1"}]
    search_util.plugin_manager.get_plugin("py").search = search
    await search_util.search("py", "q", force_reload=False)
    assert called["flag"]

def test_purge_cache(search_util):
    # Put something in cache
    search_util._store_in_cache("x", [SearchResult("py", "foo", "1")])
    assert search_util._cache
    search_util.purge_cache()
    assert not search_util._cache

@pytest.mark.asyncio
async def test_search_invalid_plugin(search_util):
    # Plugin does not exist
    res = await search_util.search("nope", "q")
    assert res == []

@pytest.mark.asyncio
async def test_plugin_returns_nonlist(search_util):
    class BadPlugin:
        async def search(self, **_): return 123
    search_util.plugin_manager.get_plugin = lambda eco: BadPlugin()
    with pytest.raises(PluginSearchError):
        await search_util.search("py", "q", raise_on_error=True)

@pytest.mark.asyncio
async def test_plugin_returns_bad_dict(search_util):
    class BadPlugin:
        async def search(self, **_): return [{"name": "ok", "version": "1"}, {"name": None, "version": "1"}, "not_a_dict"]
    search_util.plugin_manager.get_plugin = lambda eco: BadPlugin()
    results = await search_util.search("py", "q")
    assert len(results) == 1 and results[0].name == "ok"

@pytest.mark.asyncio
async def test_sorting(search_util):
    class SortedPlugin:
        async def search(self, **_): return [
            {"name": "zeta", "version": "1", "stars": 2},
            {"name": "alpha", "version": "2", "stars": 5}
        ]
    search_util.plugin_manager.get_plugin = lambda eco: SortedPlugin()
    # FIX: Removed descending=False as it's not a valid argument
    res = await search_util.search("py", "z", sort_by="name")
    assert res[0].name == "zeta" # 'zeta' comes after 'alpha'
    res2 = await search_util.search("py", "z", sort_by="stars")
    assert res2[0].name == "alpha"

@pytest.mark.asyncio
async def test_search_all_ecosystems_concurrent(monkeypatch):
    called = []
    class Plug:
        async def search(self, **_):
            called.append(1)
            await asyncio.sleep(0.01)
            return [{"name": "A", "version": "1"}]
    class Pmgr:
        def get_all_plugins(self): return {"py": Plug(), "js": Plug()}
        def get_plugin(self, eco): return Plug()
    util = SearchUtil(Pmgr(), None)
    results = await util.search_all_ecosystems("wow")
    assert set(results.keys()) == {"py", "js"}
    assert all(isinstance(v, list) for v in results.values())
    assert called.count(1) == 2

@pytest.mark.asyncio
async def test_worker_timeout(monkeypatch):
    class SlowPlugin:
        async def search(self, **_):
            await asyncio.sleep(0.2)
            return [{"name": "x", "version": "1"}]
    class PM:
        def get_plugin(self, eco): return SlowPlugin()
        def get_all_plugins(self): return {"py": SlowPlugin()}
    util = SearchUtil(PM(), None, config={"search": {"per_plugin_timeout_seconds": 0.05}})
    res = await util._search_worker("py", "z", None, raise_on_error=False)
    assert res == []