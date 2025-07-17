# upm/network_util.py

import asyncio
import ssl
import os
import sys
import tempfile
from typing import Any, Dict, Optional, Callable

# --- Conditional Imports for Networking Libraries ---
try:
    import aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False

try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, after_log
    _TENACITY_AVAILABLE = True
except ImportError:
    _TENACITY_AVAILABLE = False

# Conditional import for modern asyncio.timeout
if sys.version_info >= (3, 11):
    from asyncio import timeout as asyncio_timeout
else:
    asyncio_timeout = None

# --- UPM-Specific Imports ---
from upm.logging_utils import AUDIT_LOGGER, redact_secrets

# --- Custom Exception ---
class NetworkError(Exception):
    """Custom base exception for network-related errors in UPM."""
    def __init__(self, message: str, status_code: Optional[int] = None, url: Optional[str] = None):
        self.status_code = status_code
        self.url = redact_secrets(url) if url else "N/A"
        super().__init__(f"NetworkError: {message} (URL: {self.url}, Status: {status_code or 'N/A'})")

def _log_retry_attempt(retry_state):
    """Callback for tenacity to log retry attempts."""
    exception = retry_state.outcome.exception()
    AUDIT_LOGGER.warning(
        f"Network request failed, retrying in {retry_state.next_action.sleep:.2f}s... (Attempt {retry_state.attempt_number})",
        extra={"retry_attempt": retry_state.attempt_number, "exception": str(exception)}
    )

class NetworkUtil:
    """
    Utility for async network operations with retries, timeouts, and security.

    Note on Thread Safety & Session Management:
        An instance of this class and its `aiohttp.ClientSession` are not thread-safe.
        A single instance should be used per async context. If a custom session
        object is passed to the constructor, the caller is responsible for closing it.
    """
    DOWNLOAD_CHUNK_SIZE: int = 8192

    def __init__(self, config: Dict[str, Any], session: Optional[aiohttp.ClientSession] = None):
        """
        Initializes the NetworkUtil.

        Args:
            config: The 'network' section of the UPM config.
            session: An optional, existing session for mock injection during tests.
        """
        if not _AIOHTTP_AVAILABLE or not _TENACITY_AVAILABLE:
            raise ImportError("Libraries 'aiohttp' and 'tenacity' are required.")

        self.config = config.get("network", {})
        self.timeout_seconds = self.config.get("timeout_seconds", 30)
        self.proxy = self.config.get("proxy")
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.ca_bundle = self.config.get("ca_bundle")
        self.default_headers = self.config.get("headers", {})
        self.disable_retries = self.config.get("disable_retries", False)

        if self.ca_bundle:
            if not os.path.exists(self.ca_bundle):
                raise FileNotFoundError(f"Custom CA bundle not found at path: {self.ca_bundle}")
            if not os.access(self.ca_bundle, os.R_OK):
                raise PermissionError(f"Custom CA bundle is not readable: {self.ca_bundle}")

        self._session = session
        self._managed_session = session is None
        self._timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)

    async def __aenter__(self):
        await self._get_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._managed_session:
            await self.close()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_context = False if not self.verify_ssl else (ssl.create_default_context(cafile=self.ca_bundle) if self.ca_bundle else True)
            self._session = aiohttp.ClientSession(timeout=self._timeout, headers=self.default_headers, connector=aiohttp.TCPConnector(ssl=ssl_context))
        return self._session

    async def close(self) -> None:
        """Gracefully closes the managed aiohttp client session."""
        if self._session and not self._session.closed and self._managed_session:
            await self._session.close()
            AUDIT_LOGGER.info("Network session closed.")

    async def _request(self, method: str, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Performs an HTTP request, wrapped by retry logic if not disabled."""
        if self.disable_retries:
            return await self._perform_request(method, url, **kwargs)

        # Statically define the retry-decorated function
        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=2, max=10),
            retry=retry_if_exception_type((aiohttp.ClientConnectionError, asyncio.TimeoutError, NetworkError)),
            before_sleep=_log_retry_attempt,
            after=lambda state: AUDIT_LOGGER.info(f"Request to {redact_secrets(url)} succeeded after {state.attempt_number} attempts.") if state.attempt_number > 1 else None,
            reraise=True
        )
        async def decorated_request(m, u, **kw):
            return await self._perform_request(m, u, **kw)
        
        return await decorated_request(method, url, **kwargs)

    async def _perform_request(self, method: str, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        if not url.lower().startswith('https:'):
            raise ValueError(f"Insecure URL blocked: only HTTPS endpoints are allowed.")

        session = await self._get_session()
        redacted_url = redact_secrets(url)
        kwargs['headers'] = {**self.default_headers, **kwargs.get('headers', {})}
        if "proxy" not in kwargs and self.proxy: kwargs["proxy"] = self.proxy
        
        AUDIT_LOGGER.info(f"Requesting: {method} {redacted_url}")
        try:
            response = await session.request(method, url, **kwargs)
            AUDIT_LOGGER.debug(f"Request to {redacted_url} completed with status {response.status}")
            response.raise_for_status()
            return response
        except asyncio.CancelledError:
            AUDIT_LOGGER.warning(f"Request cancelled: {method} {redacted_url}")
            raise
        except aiohttp.ClientResponseError as e:
            raise NetworkError(message=e.message, status_code=e.status, url=url) from e
        except asyncio.TimeoutError as e:
            raise NetworkError(message="Request timed out", url=url) from e
        # FIX: Catch raw ssl.SSLError as it might be raised before aiohttp wraps it
        except ssl.SSLError as e:
            raise NetworkError(message=f"SSL certificate verification failed: {e}", url=url) from e
        except aiohttp.ClientError as e:
            raise NetworkError(message=str(e), url=url) from e

    async def get(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        return await self._request("POST", url, **kwargs)
        
    async def put(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        return await self._request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        return await self._request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        return await self._request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        return await self._request("HEAD", url, **kwargs)

    async def download_file(self, url: str, destination_path: str, progress_callback: Optional[Callable[[int, int], None]] = None, **kwargs: Any) -> str:
        """Atomically downloads a file, with progress reporting and robust timeout."""
        redacted_url = redact_secrets(url)
        tmp_file_path = ""
        
        async def download_logic():
            nonlocal tmp_file_path
            async with await self.get(url, **kwargs) as response:
                # Note: total_size is 0 if Content-Length header is missing (e.g., chunked encoding)
                total_size = int(response.headers.get('Content-Length', 0))
                bytes_downloaded = 0
                with tempfile.NamedTemporaryFile(delete=False, dir=os.path.dirname(destination_path) or '.', prefix=".upm_dl_") as tmp_file:
                    tmp_file_path = tmp_file.name
                    while True:
                        chunk = await response.content.read(self.DOWNLOAD_CHUNK_SIZE)
                        if not chunk: break
                        tmp_file.write(chunk)
                        bytes_downloaded += len(chunk)
                        if progress_callback:
                            progress_callback(bytes_downloaded, total_size)
            os.rename(tmp_file_path, destination_path)

        try:
            if asyncio_timeout:
                async with asyncio_timeout(self.timeout_seconds):
                    await download_logic()
            else:
                await asyncio.wait_for(download_logic(), timeout=self.timeout_seconds)
            
            AUDIT_LOGGER.info(f"Successfully downloaded file from {redacted_url} to {destination_path}")
            return destination_path
        except Exception as e:
            AUDIT_LOGGER.error(f"Failed to download file from {redacted_url}: {e}", exc_info=True)
            if os.path.exists(tmp_file_path):
                os.remove(tmp_file_path)
            if isinstance(e, (NetworkError, ValueError)): raise
            raise NetworkError(message=f"File download failed: {e}", url=url) from e