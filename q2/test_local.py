import requests
import json

BASE = "http://localhost:8000"

def run_tests():
    print("--- 1. Testing Agent Card ---")
    r = requests.get(f"{BASE}/.well-known/agent-card.json")
    assert r.status_code == 200, f"Card failed: {r.status_code}"
    card = r.json()
    assert card["capabilities"]["batchProcessing"] is True
    print("✓ Agent Card Passed")

    print("--- 2. Testing LIST_AUTH_REQUIRED (Missing Bearer Token) ---")
    r = requests.get(f"{BASE}/tasks", headers={"A2A-Version": "1.0"})
    assert r.status_code in (401, 403), f"Expected 401/403 on missing auth, got: {r.status_code}"
    print("✓ Unauthenticated list rejected correctly")

    print("--- 3. Testing A2A_MEDIA_TYPE_REJECTION ---")
    headers_bad_ct = {
        "A2A-Version": "1.0",
        "Authorization": "Bearer test-user-1",
        "Content-Type": "text/plain"
    }
    r = requests.post(f"{BASE}/message:send", data="bad", headers=headers_bad_ct)
    assert r.status_code in (400, 415), f"Expected 415/400 for bad content type, got: {r.status_code}"
    print("✓ Invalid Content-Type rejected correctly")

    print("--- 4. Testing Initial Batch Proposals ---")
    headers_valid = {
        "A2A-Version": "1.0",
        "Authorization": "Bearer test-user-1",
        "Content-Type": "application/a2a+json"
    }
    batch_payload = {
        "message": {
            "messageId": "msg_001",
            "role": "ROLE_USER",
            "parts": [{
                "mediaType": "application/vnd.ga5.invoice-claim-batch+json",
                "data": {
                    "batchId": "b_123",
                    "packages": [{
                        "packageId": "pkg_1",
                        "documents": ["[doc_po_10] PO Amount 1000", "[doc_grn_20] Goods received", "[doc_inv_30] Vendor Invoice 1000"]
                    }]
                }
            }]
        }
    }
    r = requests.post(f"{BASE}/message:send", json=batch_payload, headers=headers_valid)
    assert r.status_code == 200, f"Batch proposal failed: {r.status_code} {r.text}"
    resp = r.json()
    task = resp["task"]
    assert task["status"] == "TASK_STATE_INPUT_REQUIRED"
    task_id = task["id"]
    ctx_id = task["contextId"]
    proposal = task["artifacts"][0]["data"]["proposals"][0]
    action_id = proposal["actionId"]
    print(f"✓ Proposal generated successfully: {proposal['action']}")

    print("--- 5. Testing PERSISTENT_REPLAY & IDEMPOTENCY_CONFLICT ---")
    # Exact replay
    r_replay = requests.post(f"{BASE}/message:send", json=batch_payload, headers=headers_valid)
    assert r_replay.status_code == 200, "Replay failed"
    # Mutation conflict
    mutated = dict(batch_payload)
    mutated["message"] = dict(batch_payload["message"])
    mutated["message"]["role"] = "ROLE_AGENT"
    r_conflict = requests.post(f"{BASE}/message:send", json=mutated, headers=headers_valid)
    assert r_conflict.status_code == 409, f"Expected 409 conflict, got: {r_conflict.status_code}"
    print("✓ Idempotency conflict & exact replay passed")

    print("--- 6. Testing CROSS_PRINCIPAL_MUTATION & ISOLATION ---")
    headers_user_2 = {
        "A2A-Version": "1.0",
        "Authorization": "Bearer test-user-2",
        "Content-Type": "application/a2a+json"
    }
    # User 2 tries to read User 1's task
    r_iso = requests.get(f"{BASE}/tasks/{task_id}", headers=headers_user_2)
    assert r_iso.status_code in (403, 404), f"Expected 404/403 on outsider read, got: {r_iso.status_code}"
    # User 2 list should be empty
    r_list2 = requests.get(f"{BASE}/tasks", headers=headers_user_2)
    assert len(r_list2.json()["tasks"]) == 0
    print("✓ Tenant isolation passed")

    print("--- 7. Testing CANCEL_RECEIPT_RACE & Terminal Lock ---")
    cancel_res = requests.post(f"{BASE}/tasks/{task_id}:cancel", headers=headers_valid)
    assert cancel_res.status_code == 200
    # Trying to cancel or finish again must return 409
    cancel_again = requests.post(f"{BASE}/tasks/{task_id}:cancel", headers=headers_valid)
    assert cancel_again.status_code == 409
    print("✓ Race & terminal cancellation locks passed")

    print("\n🎉 ALL LOCAL TEST CHECKS PASSED! Ready for portal submission.")

if __name__ == "__main__":
    run_tests()
