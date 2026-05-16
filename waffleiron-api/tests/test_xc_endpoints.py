"""Tests for XC integration endpoints."""

import responses as responses_mock
import pytest
from fastapi.testclient import TestClient

from waffleiron_api.main import app

client = TestClient(app)


class TestXCStatus:
    def test_no_creds_configured(self):
        response = client.get("/api/v1/xc/status")
        assert response.status_code == 200
        assert response.json()["configured"] is False


class TestXCConnect:
    @responses_mock.activate
    def test_successful_connection(self):
        responses_mock.add(
            responses_mock.GET,
            "https://test.console.ves.volterra.io/api/web/custom/namespaces/system/whoami",
            json={"tenant": "test"},
            status=200,
        )
        response = client.post(
            "/api/v1/xc/connect",
            json={
                "tenant_url": "https://test.console.ves.volterra.io",
                "api_token": "token",
            },
        )
        assert response.status_code == 200
        assert response.json()["connected"] is True

    @responses_mock.activate
    def test_failed_connection(self):
        responses_mock.add(
            responses_mock.GET,
            "https://test.console.ves.volterra.io/api/web/custom/namespaces/system/whoami",
            json={"message": "unauthorized"},
            status=401,
        )
        response = client.post(
            "/api/v1/xc/connect",
            json={
                "tenant_url": "https://test.console.ves.volterra.io",
                "api_token": "bad-token",
            },
        )
        assert response.status_code == 200
        assert response.json()["connected"] is False


class TestXCNamespaces:
    @responses_mock.activate
    def test_list_namespaces(self):
        responses_mock.add(
            responses_mock.GET,
            "https://test.console.ves.volterra.io/api/web/namespaces",
            json={"items": [{"name": "ns1"}, {"name": "ns2"}]},
            status=200,
        )
        response = client.get(
            "/api/v1/xc/namespaces",
            params={
                "tenant_url": "https://test.console.ves.volterra.io",
                "api_token": "token",
            },
        )
        assert response.status_code == 200
        namespaces = response.json()["namespaces"]
        assert "shared" in namespaces
        assert "ns1" in namespaces


class TestPush:
    @responses_mock.activate
    def test_push_to_xc(self, translated_session_id):
        responses_mock.add(
            responses_mock.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/test-ns/app_firewalls",
            json={"metadata": {"name": "test"}},
            status=200,
        )
        response = client.post(
            f"/api/v1/conversions/{translated_session_id}/push",
            json={
                "namespace": "test-ns",
                "tenant_url": "https://test.console.ves.volterra.io",
                "api_token": "token",
                "objects": ["app_firewall"],
            },
        )
        assert response.status_code == 200
        results = response.json()["results"]
        assert all(r["success"] for r in results)

    @responses_mock.activate
    def test_push_unknown_object_type(self, translated_session_id):
        response = client.post(
            f"/api/v1/conversions/{translated_session_id}/push",
            json={
                "namespace": "test-ns",
                "tenant_url": "https://test.console.ves.volterra.io",
                "api_token": "token",
                "objects": ["nonexistent_type"],
            },
        )
        assert response.status_code == 200
        results = response.json()["results"]
        assert len(results) == 1
        assert results[0]["success"] is False

    def test_push_no_translation(self, created_session_id):
        response = client.post(
            f"/api/v1/conversions/{created_session_id}/push",
            json={
                "namespace": "test-ns",
                "tenant_url": "https://test.console.ves.volterra.io",
                "api_token": "token",
                "objects": ["app_firewall"],
            },
        )
        assert response.status_code == 400
