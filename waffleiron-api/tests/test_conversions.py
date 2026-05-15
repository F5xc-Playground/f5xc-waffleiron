"""Tests for conversion API endpoints."""

from fastapi.testclient import TestClient

from waffleiron_api.main import app

client = TestClient(app)


class TestCreateConversion:
    def test_upload_xml(self, minimal_xml_bytes):
        response = client.post(
            "/api/v1/conversions",
            files={"file": ("policy.xml", minimal_xml_bytes, "application/xml")},
        )
        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert data["status"] == "parsed"
        assert data["policy_name"] == "test-policy"

    def test_upload_json(self, minimal_json_bytes):
        response = client.post(
            "/api/v1/conversions",
            files={"file": ("policy.json", minimal_json_bytes, "application/json")},
        )
        assert response.status_code == 201

    def test_upload_invalid(self):
        response = client.post(
            "/api/v1/conversions",
            files={"file": ("bad.txt", b"not a policy", "text/plain")},
        )
        assert response.status_code == 422


class TestGetConversion:
    def test_get_session(self, created_session_id):
        response = client.get(f"/api/v1/conversions/{created_session_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "parsed"

    def test_get_nonexistent(self):
        response = client.get("/api/v1/conversions/nonexistent")
        assert response.status_code == 404


class TestAnalysis:
    def test_get_analysis(self, created_session_id):
        response = client.get(f"/api/v1/conversions/{created_session_id}/analysis")
        assert response.status_code == 200
        data = response.json()
        assert "summary" in data
        assert "alarm_only_signatures" in data


class TestDecisions:
    def test_submit_decisions(self, created_session_id):
        response = client.put(
            f"/api/v1/conversions/{created_session_id}/decisions",
            json={"alarm_only_signatures": [{"sig_id": 200001001, "action": "exclude"}]},
        )
        assert response.status_code == 200


class TestTranslate:
    def test_translate(self, created_session_id):
        # Submit decisions first
        client.put(
            f"/api/v1/conversions/{created_session_id}/decisions",
            json={"alarm_only_signatures": []},
        )
        response = client.post(
            f"/api/v1/conversions/{created_session_id}/translate",
            json={"namespace": "test-ns"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "app_firewall" in data["outputs"]


class TestOutputs:
    def test_list_outputs(self, translated_session_id):
        response = client.get(f"/api/v1/conversions/{translated_session_id}/outputs")
        assert response.status_code == 200
        assert "app_firewall" in response.json()["available"]

    def test_download_output(self, translated_session_id):
        response = client.get(
            f"/api/v1/conversions/{translated_session_id}/outputs/app_firewall"
        )
        assert response.status_code == 200
        assert "metadata" in response.json()


class TestReport:
    def test_json_report(self, translated_session_id):
        response = client.get(
            f"/api/v1/conversions/{translated_session_id}/report",
            headers={"Accept": "application/json"},
        )
        assert response.status_code == 200
        assert "summary" in response.json()

    def test_markdown_report(self, translated_session_id):
        response = client.get(
            f"/api/v1/conversions/{translated_session_id}/report",
            headers={"Accept": "text/markdown"},
        )
        assert response.status_code == 200
        assert "## Summary" in response.text or "# ASM" in response.text or "##" in response.text


class TestDelete:
    def test_cleanup(self, created_session_id):
        response = client.delete(f"/api/v1/conversions/{created_session_id}")
        assert response.status_code == 204
        assert client.get(f"/api/v1/conversions/{created_session_id}").status_code == 404
