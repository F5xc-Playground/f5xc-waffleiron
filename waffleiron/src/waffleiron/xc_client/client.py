"""XC API HTTP client with auth, retry, and rate limiting."""

from __future__ import annotations

import time
from typing import Any

import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from waffleiron.xc_client.config import XCConfig
from waffleiron.xc_client.errors import (
    XCAuthError,
    XCConflictError,
    XCNotFoundError,
    XCRateLimitError,
    XCServerError,
)

_DEFAULT_RPS = 2.0


class XCClient:
    """HTTP client for the F5 Distributed Cloud (XC) REST API.

    Supports token-based authentication, automatic retry on transient errors,
    and simple rate limiting.
    """

    def __init__(self, config: XCConfig, rps: float = _DEFAULT_RPS) -> None:
        self._config = config
        self._min_interval = 1.0 / rps
        self._last_request_time: float = 0.0

        self._session = requests.Session()

        # Token auth header
        if config.auth_method == "token" and config.api_token:
            self._session.headers["Authorization"] = f"APIToken {config.api_token}"
        elif config.auth_method == "p12":
            raise NotImplementedError("P12 certificate authentication is not yet supported")

        # Retry adapter for transient transport errors only.
        # Do NOT include 429 or 500 — the `responses` mock library doesn't
        # play well with urllib3 retries for those status codes.
        retry = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[502, 503, 504],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rate_limit(self) -> None:
        """Sleep if needed to honour the configured requests-per-second limit."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request_time = time.monotonic()

    def _raise_for_status(self, response: requests.Response) -> None:
        """Map HTTP error status codes to XC-specific exceptions."""
        code = response.status_code
        if code < 400:
            return

        try:
            message = response.json().get("message", response.text)
        except Exception:
            message = response.text

        if code in (401, 403):
            raise XCAuthError(message, status_code=code)
        if code == 404:
            raise XCNotFoundError(message, status_code=code)
        if code == 409:
            raise XCConflictError(message, status_code=code)
        if code == 429:
            raise XCRateLimitError(message, status_code=code)
        if code >= 500:
            raise XCServerError(message, status_code=code)

        # Catch-all for other 4xx
        raise XCServerError(f"HTTP {code}: {message}", status_code=code)

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Execute a rate-limited request and return the parsed JSON body."""
        self._rate_limit()
        url = f"{self._config.tenant_url.rstrip('/')}/{path.lstrip('/')}"
        response = self._session.request(method, url, **kwargs)
        self._raise_for_status(response)
        if not response.content:
            return {}
        return response.json()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_connection(self) -> bool:
        """Return True if the XC API is reachable and credentials are valid."""
        try:
            self._request("GET", "/api/web/custom/namespaces/system/whoami")
            return True
        except Exception:
            return False

    def list_namespaces(self) -> list[dict]:
        """Return a list of namespace objects from the XC API."""
        data = self._request("GET", "/api/web/namespaces")
        return data.get("items", [])

    def create_object(self, resource: str, namespace: str, body: dict) -> dict:
        """POST a new object and return the created resource."""
        path = f"/api/config/namespaces/{namespace}/{resource}"
        return self._request("POST", path, json=body)

    def update_object(self, resource: str, namespace: str, name: str, body: dict) -> dict:
        """PUT (replace) an existing object and return the updated resource."""
        path = f"/api/config/namespaces/{namespace}/{resource}/{name}"
        return self._request("PUT", path, json=body)

    def get_object(self, resource: str, namespace: str, name: str) -> dict:
        """GET a single object by resource type, namespace, and name."""
        path = f"/api/config/namespaces/{namespace}/{resource}/{name}"
        return self._request("GET", path)
