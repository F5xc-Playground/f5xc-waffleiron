"""Tests for XC API client (xc_client/client.py)."""

import responses
import pytest
from waffleiron.xc_client.client import XCClient
from waffleiron.xc_client.config import XCConfig
from waffleiron.xc_client.errors import XCAuthError, XCNotFoundError, XCConflictError


@pytest.fixture
def xc_config():
    return XCConfig(
        tenant_url="https://test.console.ves.volterra.io",
        api_token="test-token",
        auth_method="token",
    )


class TestAuth:
    @responses.activate
    def test_token_auth_header(self, xc_config):
        responses.add(responses.GET, "https://test.console.ves.volterra.io/api/web/namespaces",
                      json={"items": []}, status=200)
        client = XCClient(xc_config)
        client.list_namespaces()
        assert responses.calls[0].request.headers["Authorization"] == "APIToken test-token"


class TestCRUD:
    @responses.activate
    def test_create_app_firewall(self, xc_config):
        responses.add(responses.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/test-ns/app_firewalls",
            json={"metadata": {"name": "test"}}, status=200)
        client = XCClient(xc_config)
        result = client.create_object("app_firewalls", "test-ns", {"metadata": {"name": "test"}})
        assert result["metadata"]["name"] == "test"

    @responses.activate
    def test_list_namespaces(self, xc_config):
        responses.add(responses.GET,
            "https://test.console.ves.volterra.io/api/web/namespaces",
            json={"items": [{"name": "ns1"}, {"name": "ns2"}]}, status=200)
        client = XCClient(xc_config)
        ns = client.list_namespaces()
        assert len(ns) == 2


class TestErrorHandling:
    @responses.activate
    def test_401_raises_auth_error(self, xc_config):
        responses.add(responses.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/ns/app_firewalls",
            json={"message": "unauthorized"}, status=401)
        client = XCClient(xc_config)
        with pytest.raises(XCAuthError):
            client.create_object("app_firewalls", "ns", {})

    @responses.activate
    def test_409_raises_conflict(self, xc_config):
        responses.add(responses.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/ns/app_firewalls",
            json={"message": "already exists"}, status=409)
        client = XCClient(xc_config)
        with pytest.raises(XCConflictError):
            client.create_object("app_firewalls", "ns", {})


class TestSharedNamespace:
    @responses.activate
    def test_shared_ns_url(self, xc_config):
        responses.add(responses.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/shared/app_firewalls",
            json={"metadata": {"name": "test"}}, status=200)
        client = XCClient(xc_config)
        client.create_object("app_firewalls", "shared", {})
        assert "/namespaces/shared/" in responses.calls[0].request.url


class TestConnectivity:
    @responses.activate
    def test_check_connection(self, xc_config):
        responses.add(responses.GET,
            "https://test.console.ves.volterra.io/api/web/custom/namespaces/system/whoami",
            json={"tenant": "test"}, status=200)
        client = XCClient(xc_config)
        assert client.check_connection() is True
