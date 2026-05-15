"""Shared fixtures for waffleiron-api tests."""

from pathlib import Path

import pytest

from waffleiron_api.sessions import SessionStore


@pytest.fixture
def session_store() -> SessionStore:
    """Provide a fresh session store with a generous TTL."""
    return SessionStore(ttl_seconds=3600)


@pytest.fixture
def minimal_xml_bytes():
    """Read the minimal_blocking.xml fixture as bytes."""
    fixtures_path = Path(__file__).parent / "../../waffleiron/tests/fixtures"
    return (fixtures_path / "minimal_blocking.xml").read_bytes()


@pytest.fixture
def minimal_json_bytes():
    """Read the minimal_blocking.json fixture as bytes."""
    fixtures_path = Path(__file__).parent / "../../waffleiron/tests/fixtures"
    return (fixtures_path / "minimal_blocking.json").read_bytes()


@pytest.fixture
def created_session_id(minimal_xml_bytes):
    """Upload an XML policy and return the session ID."""
    from fastapi.testclient import TestClient

    from waffleiron_api.main import app

    client = TestClient(app)
    response = client.post(
        "/api/v1/conversions",
        files={"file": ("policy.xml", minimal_xml_bytes, "application/xml")},
    )
    return response.json()["id"]


@pytest.fixture
def translated_session_id(minimal_xml_bytes):
    """Upload, decide, and translate — return the session ID."""
    from fastapi.testclient import TestClient

    from waffleiron_api.main import app

    client = TestClient(app)
    # Upload
    r = client.post(
        "/api/v1/conversions",
        files={"file": ("policy.xml", minimal_xml_bytes, "application/xml")},
    )
    sid = r.json()["id"]
    # Submit empty decisions
    client.put(f"/api/v1/conversions/{sid}/decisions", json={"alarm_only_signatures": []})
    # Translate
    client.post(f"/api/v1/conversions/{sid}/translate", json={"namespace": "test-ns"})
    return sid
