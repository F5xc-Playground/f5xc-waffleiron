"""Shared fixtures for waffleiron-api tests."""

import pytest

from waffleiron_api.sessions import SessionStore


@pytest.fixture
def session_store() -> SessionStore:
    """Provide a fresh session store with a generous TTL."""
    return SessionStore(ttl_seconds=3600)
