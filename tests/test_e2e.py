"""End-to-end integration test for the full WaffleIron conversion workflow."""

from pathlib import Path

from fastapi.testclient import TestClient

from waffleiron_api.main import app

client = TestClient(app)


def test_full_conversion_workflow():
    # 1. Upload
    fixture_path = (
        Path(__file__).resolve().parent.parent
        / "waffleiron"
        / "tests"
        / "fixtures"
        / "mature_tuned.xml"
    )
    with open(fixture_path, "rb") as f:
        resp = client.post("/api/v1/conversions", files={"file": ("policy.xml", f)})
    assert resp.status_code == 201
    session_id = resp.json()["id"]

    # 2. Get analysis
    resp = client.get(f"/api/v1/conversions/{session_id}/analysis")
    assert resp.status_code == 200
    analysis = resp.json()
    assert analysis["summary"]["decisions_required"] > 0

    # 3. Submit decisions (exclude all alarm-only sigs)
    decisions = {
        "alarm_only_signatures": [
            {"sig_id": s["sig_id"], "action": "exclude"}
            for s in analysis["alarm_only_signatures"]
        ],
    }
    resp = client.put(f"/api/v1/conversions/{session_id}/decisions", json=decisions)
    assert resp.status_code == 200

    # 4. Translate
    resp = client.post(
        f"/api/v1/conversions/{session_id}/translate",
        json={"namespace": "test-ns"},
    )
    assert resp.status_code == 200
    outputs = resp.json()["outputs"]
    assert "app_firewall" in outputs

    # 5. Get outputs
    resp = client.get(f"/api/v1/conversions/{session_id}/outputs/app_firewall")
    assert resp.status_code == 200
    app_fw = resp.json()
    assert app_fw["metadata"]["namespace"] == "test-ns"

    # 6. Get gap report
    resp = client.get(
        f"/api/v1/conversions/{session_id}/report",
        headers={"Accept": "text/markdown"},
    )
    assert resp.status_code == 200
    assert "##" in resp.text  # Markdown headings present

    # 7. Cleanup
    resp = client.delete(f"/api/v1/conversions/{session_id}")
    assert resp.status_code == 204
