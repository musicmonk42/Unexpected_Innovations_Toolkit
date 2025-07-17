# upm/search_util.py

import asyncio
import time
import copy # FIX: Import the copy module
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Tuple

from upm.plugin_manager import PluginManager
from upm.network_util import NetworkUtil, NetworkError
from upm.logging_utils import AUDIT_LOGGER

# --- Custom Exceptions ---
class PluginSearchError(Exception):
    """Custom exception for errors during a plugin's search execution, with added context."""
    def __init__(self, message: str, ecosystem: str, returned_type: Optional[str] = None):
        self.ecosystem = ecosystem
        self.returned_type = returned_type
        super().__init__(f"Plugin '{ecosystem}' search error: {message}. Returned type: {returned_type or 'N/A'}")

# --- Standardized Data Structure ---
@dataclass(slots=True)
class SearchResult:
    """A standardized data object for a single search result."""
    ecosystem: str
    name: str
    version: str
    description: Optional[str] = None
    url: Optional[str] = None
    license: Optional[str] = None
    extra_data: Dict[str, Any] = field(default_factory=dict, repr=False)


class SearchUtil:
    """
    Utility for searching packages. It coordinates plugins, unifies results, and provides caching.
    """
    def __init__(
        self,
        plugin_manager: PluginManager,
        network_util: NetworkUtil,
        config: Optional[Dict[str, Any]] = None,
        clock: Callable[[], float] = time.time
    ):
        """
        Initializes the SearchUtil.

        Args:
            plugin_manager: An instance of PluginManager to access ecosystem plugins.
            network_util: An instance of NetworkUtil, which may be used by plugins.
            config: The 'search' or global configuration dictionary. Defaults can be set here.
            clock: A callable that returns the current time. Used for making cache
                   expiry logic deterministic during tests.
        """
        search_config = config.get("search", {}) if config else {}
        self.plugin_manager = plugin_manager
        self.network_util = network_util
        
        # Caching: A pluggable backend adapter supporting __getitem__, __setitem__, and clear
        # could be injected here for scalability (e.g., Redis, diskcache).
        self._cache: Dict[str, Tuple[float, List[SearchResult]]] = {}
        self._global_cache_ttl = search_config.get("cache_ttl_seconds", 300)
        self._per_ecosystem_ttl = search_config.get("per_ecosystem_ttl", {})

        # Concurrency
        concurrency_limit = search_config.get("concurrency_limit", 5)
        self.per_plugin_timeout = search_config.get("per_plugin_timeout_seconds", 20)
        self._semaphore = asyncio.Semaphore(concurrency_limit)
        
        self.clock = clock

    def _get_cache_key(self, ecosystem: str, query: str, filters: Optional[Dict[str, Any]]) -> str:
        """Creates a consistent key for caching search results."""
        filter_str = str(sorted(filters.items())) if filters else ""
        return f"{ecosystem}:{query}:{filter_str}"

    def _get_from_cache(self, key: str, ttl: int) -> Optional[List[SearchResult]]:
        """Retrieves a result from the cache if it's not expired."""
        cached_item = self._cache.get(key)
        if cached_item:
            timestamp, data = cached_item
            if self.clock() - timestamp < ttl:
                AUDIT_LOGGER.info(f"Search cache hit for key: '{key}'")
                # Observability Hook: A cache hit counter metric could be incremented here.
                # FIX: Return a deep copy to prevent mutation of the cached object
                return copy.deepcopy(data)
        
        AUDIT_LOGGER.debug(f"Search cache miss for key: '{key}'")
        return None

    def _store_in_cache(self, key: str, data: List[SearchResult]):
        """Stores a result in the cache with a timestamp."""
        self._cache[key] = (self.clock(), data)
        AUDIT_LOGGER.debug(f"Stored search result in cache with key: '{key}'")

    def purge_cache(self):
        """Clears the entire search cache."""
        self._cache.clear()
        AUDIT_LOGGER.info("Search cache has been purged.")

    async def search(
        self,
        ecosystem: str,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        sort_by: Optional[str] = None,
        force_reload: bool = False,
        raise_on_error: bool = False
    ) -> List[SearchResult]:
        """
        Searches a single ecosystem with caching, validation, and filtering.

        Args:
            ecosystem: The name of the ecosystem to search in.
            query: The search term.
            filters: A dictionary of key-value pairs to filter results.
            sort_by: An optional field name to sort results by.
            force_reload: If True, bypasses the cache to fetch fresh results.
            raise_on_error: If True, raises exceptions instead of returning an empty list.
        """
        if not isinstance(ecosystem, str) or not ecosystem.strip() or not isinstance(query, str) or not query.strip():
            AUDIT_LOGGER.warning("Search failed: ecosystem and query must be non-empty strings.")
            return []
            
        if sort_by and not hasattr(SearchResult, sort_by):
            AUDIT_LOGGER.warning(f"Attempting to sort by non-standard key '{sort_by}'. Results will depend on plugin's 'extra_data'.")

        ttl = self._per_ecosystem_ttl.get(ecosystem, self._global_cache_ttl)
        cache_key = self._get_cache_key(ecosystem, query, filters)
        if not force_reload:
            if (cached_results := self._get_from_cache(cache_key, ttl)) is not None:
                # Apply sorting to the cached results if needed
                if sort_by:
                    cached_results.sort(key=lambda r: getattr(r, sort_by, r.extra_data.get(sort_by)), reverse=True)
                return cached_results

        plugin = self.plugin_manager.get_plugin(ecosystem)
        if not plugin:
            AUDIT_LOGGER.warning(f"Search failed: No plugin found for '{ecosystem}'.")
            return []

        try:
            start_time = self.clock()
            raw_results = await plugin.search(query=query, filters=filters, sort_by=sort_by)
            # Observability Hook: A search latency metric could be recorded here.
            
            if not isinstance(raw_results, list):
                raise PluginSearchError(f"Plugin did not return a list.", ecosystem=ecosystem, returned_type=type(raw_results).__name__)

            normalized_results = []
            for res in raw_results:
                if not isinstance(res, dict):
                    AUDIT_LOGGER.warning(f"Plugin '{ecosystem}' returned a non-dict item in its result list. Skipping.")
                    continue
                if not (res.get("name") and res.get("version")):
                    AUDIT_LOGGER.warning(f"Plugin '{ecosystem}' result missing 'name' or 'version'. Skipping: {res}")
                    continue
                normalized_results.append(SearchResult(
                    ecosystem=ecosystem, name=res["name"], version=res["version"],
                    description=res.get("description"), url=res.get("url"), license=res.get("license"),
                    extra_data={k: v for k, v in res.items() if k not in {'name', 'version', 'description', 'url', 'license'}}
                ))
            
            if sort_by:
                normalized_results.sort(key=lambda r: getattr(r, sort_by, r.extra_data.get(sort_by)), reverse=True)
            
            self._store_in_cache(cache_key, normalized_results)
            AUDIT_LOGGER.info(f"Search success for '{query}' in '{ecosystem}'. Found {len(normalized_results)} results.")
            return normalized_results
        except (NetworkError, asyncio.TimeoutError, PluginSearchError) as e:
            AUDIT_LOGGER.error(f"Search failed in '{ecosystem}': {e}", exc_info=True)
            if raise_on_error: raise
            return []
        except Exception as e:
            AUDIT_LOGGER.critical(f"Unexpected search error in '{ecosystem}': {e}", exc_info=True)
            if raise_on_error: raise
            return []

    async def _search_worker(
        self, ecosystem: str, query: str, filters: Optional[Dict[str, Any]], raise_on_error: bool
    ) -> List[SearchResult]:
        """Worker to run a single search with a semaphore and timeout."""
        async with self._semaphore:
            try:
                return await asyncio.wait_for(
                    self.search(ecosystem, query, filters, force_reload=True, raise_on_error=raise_on_error),
                    timeout=self.per_plugin_timeout
                )
            except asyncio.TimeoutError:
                AUDIT_LOGGER.error(f"Search timed out for ecosystem '{ecosystem}' after {self.per_plugin_timeout}s.")
                if raise_on_error: raise
                return []

    async def search_all_ecosystems(
        self, query: str, filters: Optional[Dict[str, Any]] = None, raise_on_error: bool = False
    ) -> Dict[str, List[SearchResult]]:
        """
        Searches concurrently across all ecosystems. Returns partial results unless raise_on_error is True.
        """
        if not isinstance(query, str) or not query.strip():
            AUDIT_LOGGER.warning("Search-all failed: 'query' must be a non-empty string.")
            return {}

        all_plugins = self.plugin_manager.get_all_plugins()
        if not all_plugins: return {}
            
        tasks = {eco_name: self._search_worker(eco_name, query, filters, raise_on_error) for eco_name in all_plugins}
        
        results = await asyncio.gather(*tasks.values(), return_exceptions=raise_on_error)
        
        return {name: result for name, result in zip(tasks.keys(), results) if not isinstance(result, Exception)}

if __name__ == '__main__':
    # This block demonstrates functionality and can be used for rapid TDD.
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    
    class MockPlugin:
        async def search(self, **kwargs): await asyncio.sleep(0.1); return [{"name": "mock-pkg", "version": "1.0"}]
    class MockPluginManager:
        def get_plugin(self, eco): return MockPlugin()
        def get_all_plugins(self): return {"mock": MockPlugin()}

    async def demo():
        searcher = SearchUtil(MockPluginManager(), None)
        print("--- Running single search ---")
        results = await searcher.search("mock", "test")
        assert len(results) == 1
        print(f"Got result: {results[0]}")
        print("\n--- Running search-all ---")
        all_results = await searcher.search_all_ecosystems("test")
        assert "mock" in all_results and len(all_results["mock"]) == 1
        print(f"Got all results: {all_results}")

    asyncio.run(demo())