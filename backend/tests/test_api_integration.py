import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.init_db import init_db
from app.services.analysis_orchestrator import run_full_case_analysis


@pytest.mark.asyncio
async def test_full_platform_api_workflow():
    """Verify full end-to-end API lifecycle from healthcheck to ingestion, analysis, and report generation."""
    # Initialize DB schema and seed accounts
    await init_db()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Health check
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "OPERATIONAL"

        # 2. Authenticate default analyst
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@phishscope.local", "password": "AnalystPass123!"}
        )
        assert login_resp.status_code == 200
        token_data = login_resp.json()
        assert "access_token" in token_data
        token = token_data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 3. List available sample scenarios
        samples_resp = await client.get("/api/v1/ingest/samples", headers=headers)
        assert samples_resp.status_code == 200
        samples = samples_resp.json()
        assert len(samples) >= 4

        # 4. Ingest sample scenario: Microsoft 365 Credential Harvest
        ingest_resp = await client.post("/api/v1/ingest/sample/phish_m365", headers=headers)
        assert ingest_resp.status_code == 200
        ingest_data = ingest_resp.json()
        case_id = ingest_data["case_id"]
        assert case_id is not None
        assert ingest_data["status"] == "ANALYSING"

        # 5. Run full forensic pipeline on case
        await run_full_case_analysis(case_id)

        # 6. Retrieve Case Detail
        case_resp = await client.get(f"/api/v1/cases/{case_id}", headers=headers)
        assert case_resp.status_code == 200
        case_detail = case_resp.json()
        
        # Verify genuine analysis results
        assert case_detail["risk_score"] >= 50
        assert case_detail["risk_level"] in ("HIGH", "CRITICAL")
        assert len(case_detail["findings"]) > 0
        assert len(case_detail["indicators"]) > 0
        assert case_detail["auth_summary"] is not None
        assert case_detail["auth_summary"]["mismatches"]["display_name_spoofing"] is True

        # 7. Add an Analyst Note
        note_resp = await client.post(
            f"/api/v1/notes/{case_id}",
            json={"note_text": "Investigated sender infrastructure. IP verified on known bulletproof host.", "action_type": "NOTE"},
            headers=headers
        )
        assert note_resp.status_code == 200

        # 8. Download Forensic PDF Report
        pdf_resp = await client.get(f"/api/v1/reports/{case_id}/pdf", headers=headers)
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["content-type"] == "application/pdf"
        assert pdf_resp.content.startswith(b"%PDF")

        # 9. Download Forensic JSON Export
        json_resp = await client.get(f"/api/v1/reports/{case_id}/json", headers=headers)
        assert json_resp.status_code == 200
        json_export = json_resp.json()
        assert json_export["export_metadata"]["case_id"] == case_id
        assert len(json_export["findings"]) > 0

        # 10. Query Standalone Threat Intel Lookup
        intel_resp = await client.post(
            "/api/v1/indicators/lookup",
            json={"indicator": "micros0ft-account-verify.com"},
            headers=headers
        )
        assert intel_resp.status_code == 200
        intel_data = intel_resp.json()
        assert intel_data["type"] == "DOMAIN"
        assert intel_data["defanged"] == "micros0ft-account-verify[.]com"

        # 11. Dashboard Metrics
        metrics_resp = await client.get("/api/v1/dashboard/metrics", headers=headers)
        assert metrics_resp.status_code == 200
        metrics = metrics_resp.json()
        assert metrics["total_cases"] >= 1
        assert metrics["risk_distribution"]["critical"] + metrics["risk_distribution"]["high"] >= 1
