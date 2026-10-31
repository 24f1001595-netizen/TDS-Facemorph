import requests
import json

BASE = "http://localhost:8002"

def test_incident_agent():
    print("--- 1. Testing Validation Probe (Malformed Request) ---")
    r_bad = requests.post(f"{BASE}/v2/incidents", json={"invalid": "payload"})
    assert r_bad.status_code in (400, 422), f"Expected 400/422, got {r_bad.status_code}"
    print("✓ Malformed probe correctly rejected with 400/422")

    print("--- 2. Testing Initial Proposal (POST /v2/incidents) ---")
    run_id = "test_run_101"
    init_payload = {
        "profile": "ga5-incident-agent/v2",
        "runId": run_id,
        "agentName": "incident-response",
        "publicMarker": "marker-safe-telemetry",
        "sensitive": {"accessToken": "secret-token-never-leak", "privateNote": "private"},
        "incident": {
            "incidentId": "inc_001",
            "title": "Payment gateway latency spike",
            "service": "payment-api",
            "severity": "SEV-1",
            "transcript": "[ev_101] Database connections exhausted\n[ev_102] Latency increased to 4500ms\n[ev_103] Normal customer traffic",
            "allowedRootCauses": ["database_connection_exhaustion", "network_partition"]
        },
        "toolCatalog": [
            {"name": "query_metrics", "description": "Query metrics", "inputSchema": {}},
            {"name": "rollback_deployment", "description": "Rollback deployment", "inputSchema": {}}
        ],
        "policy": {
            "maximumDiagnostics": 3,
            "effectTools": ["rollback_deployment"],
            "approvalRequiredFor": ["rollback_deployment"],
            "doNotExport": ["sensitive.accessToken"]
        }
    }
    r_init = requests.post(f"{BASE}/v2/incidents", json=init_payload)
    assert r_init.status_code == 200, f"Failed init: {r_init.status_code} {r_init.text}"
    init_data = r_init.json()
    assert init_data["status"] == "waiting"
    assert len(init_data["dispatches"]) >= 1
    diag = init_data["dispatches"][0]
    action_id = diag["actionId"]
    call_id = diag["callId"]
    print("✓ Initial proposal passed: rootCause =", init_data["diagnosis"]["rootCause"])

    print("--- 3. Testing GET /v2/incidents/{runId} (The Probe That Previously Failed) ---")
    r_get = requests.get(f"{BASE}/v2/incidents/{run_id}")
    assert r_get.status_code == 200, f"Expected 200 on GET, got {r_get.status_code}: {r_get.text}"
    get_data = r_get.json()
    assert get_data["runId"] == run_id
    print("✓ GET /v2/incidents/{runId} passed with HTTP 200 (422 is resolved!)")

    print("--- 4. Testing 503 Retry Lifecycle ---")
    r_503 = requests.post(f"{BASE}/v2/incidents/{run_id}/receipts", json={
        "receiptId": "rcpt_503_test",
        "outcomes": [{
            "actionId": action_id,
            "callId": call_id,
            "attempt": 1,
            "status": 503,
            "resultClass": "temporary_error",
            "nonce": "nonce_503"
        }]
    })
    assert r_503.status_code == 200
    res_503 = r_503.json()
    assert res_503["dispatches"][0]["attempt"] == 2
    print("✓ 503 correctly triggered retry with attempt=2")

    print("--- 5. Testing Diagnostic Success -> Approval Gate Transition ---")
    r_diag_ok = requests.post(f"{BASE}/v2/incidents/{run_id}/receipts", json={
        "receiptId": "rcpt_success_test",
        "outcomes": [{
            "actionId": action_id,
            "callId": call_id,
            "attempt": 2,
            "status": 200,
            "resultClass": "diagnosis_confirmed",
            "nonce": "nonce_ok_123"
        }]
    })
    assert r_diag_ok.status_code == 200
    res_appr = r_diag_ok.json()
    assert len(res_appr.get("approvals", [])) == 1
    approval_id = res_appr["approvals"][0]["approvalId"]
    print(f"✓ Risky effect paused at approval gate: approvalId = {approval_id}")

    print("--- 6. Testing Approval Grant -> Terminal State ---")
    r_final = requests.post(f"{BASE}/v2/incidents/{run_id}/receipts", json={
        "receiptId": "rcpt_appr_grant",
        "approvals": [{
            "approvalId": approval_id,
            "decision": "approved",
            "nonce": "nonce_appr_final"
        }]
    })
    assert r_final.status_code == 200
    print("✓ Approval receipt processed successfully")

    print("--- 7. Verifying Final Stored State & OTLP Telemetry ---")
    r_terminal = requests.get(f"{BASE}/v2/incidents/{run_id}")
    assert r_terminal.status_code == 200
    t_data = r_terminal.json()
    assert t_data["status"] == "completed"
    assert "otlp" in t_data
    spans = t_data["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert any(s["name"] == "chat incident-plan" for s in spans)
    assert any(s["name"] == "approval_gate" for s in spans)
    print("✓ Final OTLP trace topology verified")

    print("--- 8. Redaction Verification ---")
    serialized = json.dumps(t_data)
    assert "secret-token-never-leak" not in serialized, "SECURITY LEAK: accessToken leaked into output!"
    print("✓ Redaction verified: zero sensitive tokens leaked")

    print("\n🎉 ALL TESTS PASSED! Ready for portal submission.")

if __name__ == "__main__":
    test_incident_agent()
