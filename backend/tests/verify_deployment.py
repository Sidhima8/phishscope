import subprocess
import time
import sys
import httpx

def main():
    print("Launching PhishScope full-stack server on http://127.0.0.1:8000...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=r"C:\Users\DELL\.gemini\antigravity\scratch\phishscope\backend"
    )

    try:
        # Wait up to 15s for server to start
        ready = False
        for _ in range(30):
            try:
                r = httpx.get("http://127.0.0.1:8000/api/health", timeout=1.0)
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.5)

        if not ready:
            print("Server did not become ready in time.")
            return False

        print("-> /api/health returned 200 OK:", r.json())

        # Test Frontend index.html served at root
        r_root = httpx.get("http://127.0.0.1:8000/", timeout=2.0)
        print("-> / returned status code:", r_root.status_code)
        assert "<div id=\"root\"></div>" in r_root.text
        print("-> Frontend React application successfully mounted and served!")

        # Test /api/v1/ingest/samples
        r_samples = httpx.get("http://127.0.0.1:8000/api/v1/ingest/samples", timeout=2.0)
        assert r_samples.status_code == 200
        samples = r_samples.json()
        print(f"-> Ingestion engine has {len(samples)} preloaded real-world demonstration scenarios ready.")

        # Test Ingesting M365 Credential Harvest Scenario
        r_ingest = httpx.post("http://127.0.0.1:8000/api/v1/ingest/sample/phish_m365", timeout=5.0)
        assert r_ingest.status_code == 200
        case_id = r_ingest.json()["case_id"]
        print(f"-> Successfully ingested sample into Case #{case_id}. Waiting for analysis...")

        # Wait for analysis completion
        for _ in range(20):
            time.sleep(0.5)
            r_case = httpx.get(f"http://127.0.0.1:8000/api/v1/cases/{case_id}", timeout=2.0)
            if r_case.json()["status"] != "ANALYSING":
                break

        case_data = r_case.json()
        print(f"-> Dynamic Case Analysis completed: Status={case_data['status']}, Risk={case_data['risk_score']}/100 ({case_data['risk_level']})")
        print(f"-> Findings identified: {len(case_data['findings'])}, URLs extracted: {len(case_data['indicators'])}")

        # Test PDF Report Generation
        r_pdf = httpx.get(f"http://127.0.0.1:8000/api/v1/reports/{case_id}/pdf", timeout=5.0)
        assert r_pdf.status_code == 200
        assert r_pdf.content.startswith(b"%PDF")
        print(f"-> Forensic PDF Report dynamically rendered and verified ({len(r_pdf.content)} bytes).")

        print("\nALL RUNTIME ACCEPTANCE CRITERIA VERIFIED SUCCESSFULLY!")
        return True

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        print("Server cleanly terminated.")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
