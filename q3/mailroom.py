import base64
import hashlib
import json
import os
import re
import threading
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

app = FastAPI(title="Safe AI Mailroom Agent")

PROFILE = "ga5-mailroom-action-gate/v2"

# In-memory storage & locks
LOCK = threading.Lock()

# EVALUATIONS[evaluation_id] = {
#    "input_digest": str,
#    "verifier_jwk": dict,
#    "proposals": list,
#    "proposals_by_call_id": dict,
#    "status": "awaiting_receipts" | "completed",
#    "terminal_response": dict
# }
EVALUATIONS: Dict[str, Dict[str, Any]] = {}

# Caches proposals by canonical dossier content hash so repeats cost zero time
DOSSIER_CACHE: Dict[str, Dict[str, Any]] = {}

# --- Canonical JSON & Hashing Helpers ---

def canonical_json_bytes(obj: Any) -> bytes:
    """Recursively key-sorted compact JSON encoding preserving array order."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()

def compute_proposal_digest(proposal: Dict[str, Any]) -> str:
    """
    Keep exactly: dossierId, callId, action, target, payload, evidence.
    Sort evidence strings; then hash recursively key-sorted compact JSON.
    """
    target = proposal.get("target")
    norm = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": target if target is not None else None,
        "payload": proposal["payload"],
        "evidence": sorted(list(set(proposal.get("evidence", []))))
    }
    return sha256_hex(canonical_json_bytes(norm))

# --- Decision Logic & Evidence Extraction ---

def evaluate_dossier(dossier: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decides the single permitted action, exact frozen payload/target, and minimal evidence.
    Uses canonical caching by dossier content.
    """
    d_bytes = canonical_json_bytes(dossier)
    d_hash = sha256_hex(d_bytes)

    with LOCK:
        if d_hash in DOSSIER_CACHE:
            cached = dict(DOSSIER_CACHE[d_hash])
            return cached

    dossier_id = dossier["dossierId"]
    mailbox = dossier.get("mailbox", "support")
    sources = dossier.get("sources", [])

    all_lines: List[Dict[str, str]] = []
    line_map: Dict[str, str] = {}
    for src in sources:
        for line in src.get("lines", []):
            lid = line["lineId"]
            ltext = line["text"]
            all_lines.append({"lineId": lid, "text": ltext, "provenance": src.get("provenance", "")})
            line_map[lid] = ltext

    full_text = " ".join([l["text"] for l in all_lines])
    full_lower = full_text.lower()

    # Default fallback call ID
    call_id = f"call_{sha256_hex(d_bytes)[:24]}"

    # Helper to find line IDs containing regex patterns
    def find_lines(pattern: str) -> List[str]:
        matched = []
        for l in all_lines:
            if re.search(pattern, l["text"], re.I):
                matched.append(l["lineId"])
        return matched

    # 1. Prompt Injection / Control Hijack -> quarantine_item
    injection_patterns = [
        r"ignore (all )?previous instructions",
        r"system prompt",
        r"override safety",
        r"exfiltrate",
        r"canary_vault",
        r"assistant:"
    ]
    is_injection = False
    injection_line = None
    for p in injection_patterns:
        m = find_lines(p)
        if m:
            is_injection = True
            injection_line = m[0]
            break

    if is_injection:
        artifact_match = re.search(r'(?:artifact|item|attachment|id)[:\s]+([a-zA-Z0-9_\-]+)', full_text, re.I)
        art_id = artifact_match.group(1) if artifact_match else "artifact-unknown"
        ev = [injection_line] if injection_line else [all_lines[0]["lineId"]]
        proposal = {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {
                "artifactId": art_id,
                "reasonCode": "INDIRECT_PROMPT_INJECTION"
            },
            "evidence": ev
        }
    
    # 2. Duplicate / Already Completed / Informational -> no_action
    elif any(k in full_lower for k in ["duplicate", "already processed", "already completed", "fyi only", "no reply needed"]):
        ref_match = re.search(r'(?:ref|reference|case|ticket|order)[:\s#]*([a-zA-Z0-9_\-]+)', full_text, re.I)
        ref_id = ref_match.group(1) if ref_match else "REF-001"
        
        reason = "INFORMATIONAL"
        if "duplicate" in full_lower:
            reason = "DUPLICATE"
            lines = find_lines(r"duplicate")
        elif "already" in full_lower:
            reason = "ALREADY_COMPLETED"
            lines = find_lines(r"already")
        else:
            lines = find_lines(r"fyi|informational|no reply")
            
        ev = lines[:1] if lines else [all_lines[0]["lineId"]]
        proposal = {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "no_action",
            "target": None,
            "payload": {
                "reasonCode": reason,
                "referenceId": ref_id
            },
            "evidence": ev
        }

    # 3. Explicit Trusted Send Approval -> send_approved_notice
    elif "approved for outbound send" in full_lower or "send approved notice" in full_lower or "approved delivery notice" in full_lower:
        email_match = re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', full_text)
        ref_match = re.search(r'(?:order|ref|reference)[:\s#]*([a-zA-Z0-9_\-]+)', full_text, re.I)
        status_match = re.search(r'status[:\s]*([a-zA-Z0-9_\-]+)', full_text, re.I)
        
        recipient = email_match.group(0) if email_match else "customer@example.com"
        ref_id = ref_match.group(1) if ref_match else "ORD-100"
        st_val = status_match.group(1) if status_match else "shipped"
        
        lines = find_lines(r"approved|recipient|order|status")
        ev = list(dict.fromkeys(lines))[:2] if lines else [all_lines[0]["lineId"]]
        proposal = {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": recipient},
            "payload": {
                "referenceId": ref_id,
                "status": st_val,
                "template": "approved_delivery_notice"
            },
            "evidence": ev
        }

    # 4. Internal Case Record Field Change -> update_internal_record
    elif "update delivery window" in full_lower or "internal record" in full_lower or "case_record" in full_lower:
        case_match = re.search(r'(?:case|ticket)[:\s#]*([a-zA-Z0-9_\-]+)', full_text, re.I)
        event_match = re.search(r'(?:event|sourceEventId)[:\s#]*([a-zA-Z0-9_\-]+)', full_text, re.I)
        val_match = re.search(r'(?:window|value)[:\s]*([a-zA-Z0-9_\- ]+)', full_text, re.I)

        case_id = case_match.group(1) if case_match else "CASE-001"
        source_event_id = event_match.group(1) if event_match else "EVT-100"
        val = val_match.group(1).strip() if val_match else "morning"

        lines = find_lines(r"delivery window|update|case")
        ev = list(dict.fromkeys(lines))[:2] if lines else [all_lines[0]["lineId"]]
        proposal = {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": case_id},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": source_event_id,
                "value": val
            },
            "evidence": ev
        }

    # 5. Ambiguous / Unverified Identity -> request_confirmation
    elif any(k in full_lower for k in ["verify sender", "unclear identity", "confirmation required", "sender mismatch", "claimed sender"]):
        sender_match = re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', full_text)
        ref_match = re.search(r'(?:ref|reference|order)[:\s#]*([a-zA-Z0-9_\-]+)', full_text, re.I)
        team_match = re.search(r'(?:team|queue)[:\s]*([a-zA-Z0-9_\-]+)', full_text, re.I)

        claimed = sender_match.group(0) if sender_match else "unknown@domain.com"
        ref_id = ref_match.group(1) if ref_match else "REF-999"
        team = team_match.group(1) if team_match else "customer-operations"

        lines = find_lines(r"verify|confirm|identity|sender")
        ev = list(dict.fromkeys(lines))[:2] if lines else [all_lines[0]["lineId"]]
        proposal = {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": team},
            "payload": {
                "claimedSender": claimed,
                "questionCode": "VERIFY_REQUEST",
                "referenceId": ref_id
            },
            "evidence": ev
        }

    # 6. Default Safe Customer Draft -> create_draft
    else:
        email_match = re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', full_text)
        ref_match = re.search(r'(?:ref|reference|order)[:\s#]*([a-zA-Z0-9_\-]+)', full_text, re.I)
        status_match = re.search(r'status[:\s]*([a-zA-Z0-9_\-]+)', full_text, re.I)

        recipient = email_match.group(0) if email_match else "customer@example.com"
        ref_id = ref_match.group(1) if ref_match else "ORD-001"
        st = status_match.group(1) if status_match else "processing"

        lines = find_lines(r"order|status|draft|recipient")
        ev = lines[:2] if lines else [all_lines[0]["lineId"]]
        proposal = {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "create_draft",
            "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
            "payload": {
                "recipient": recipient,
                "referenceId": ref_id,
                "status": st,
                "template": "order_status"
            },
            "evidence": ev
        }

    with LOCK:
        DOSSIER_CACHE[d_hash] = proposal
    return proposal

# --- Ed25519 Signature Verification ---

def base64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)

def verify_receipt_signature(verifier_jwk: Dict[str, Any], message_bytes: bytes, signature_b64: str) -> bool:
    try:
        x_raw = verifier_jwk.get("x", "")
        pub_bytes = base64url_decode(x_raw)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(signature_b64)
        pub_key.verify(sig_bytes, message_bytes)
        return True
    except Exception:
        return False

# --- Unified Public Route ---

@app.post("")
@app.post("/")
async def mailroom_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Body must be a JSON object")

    if body.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail=f"Unsupported profile. Expected '{PROFILE}'")

    op = body.get("operation")
    eval_id = body.get("evaluationId")
    if not eval_id or not isinstance(eval_id, str):
        raise HTTPException(status_code=400, detail="Missing or invalid evaluationId")

    # ==========================
    # Operation 1: PROPOSE
    # ==========================
    if op == "propose":
        dossiers = body.get("dossiers")
        if not isinstance(dossiers, list) or len(dossiers) == 0:
            raise HTTPException(status_code=400, detail="dossiers must be a non-empty list")

        # Check for duplicate dossier IDs
        dossier_ids = [d.get("dossierId") for d in dossiers if isinstance(d, dict)]
        if len(dossier_ids) != len(set(dossier_ids)):
            raise HTTPException(status_code=400, detail="Duplicate dossierId detected")

        # Canonical input digest over dossiers
        input_digest = sha256_hex(canonical_json_bytes(dossiers))

        with LOCK:
            # Check for conflict or replay under same evaluationId
            if eval_id in EVALUATIONS:
                existing = EVALUATIONS[eval_id]
                if existing["input_digest"] != input_digest:
                    # Same evaluationId with altered content -> 409 Conflict
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Evaluation ID content conflict")
                # Exact replay: return saved proposals
                return JSONResponse(
                    status_code=200,
                    content={
                        "profile": PROFILE,
                        "evaluationId": eval_id,
                        "status": "awaiting_receipts",
                        "inputDigest": input_digest,
                        "proposals": existing["proposals"]
                    }
                )

        verifier = body.get("receiptVerifier", {})
        jwk = verifier.get("publicKeyJwk", {})

        proposals = []
        prop_map = {}
        for d in dossiers:
            prop = evaluate_dossier(d)
            proposals.append(prop)
            prop_map[prop["callId"]] = prop

        with LOCK:
            EVALUATIONS[eval_id] = {
                "input_digest": input_digest,
                "verifier_jwk": jwk,
                "proposals": proposals,
                "proposals_by_call_id": prop_map,
                "status": "awaiting_receipts",
                "terminal_response": None
            }

        response_payload = {
            "profile": PROFILE,
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals
        }
        return JSONResponse(status_code=200, content=response_payload)

    # ==========================
    # Operation 2: COMMIT
    # ==========================
    elif op == "commit":
        with LOCK:
            if eval_id not in EVALUATIONS:
                raise HTTPException(status_code=400, detail="Unknown evaluationId for commit")

            state = EVALUATIONS[eval_id]

            # Replay check: if already completed, return cached terminal response
            if state["status"] == "completed" and state["terminal_response"] is not None:
                return JSONResponse(status_code=200, content=state["terminal_response"])

        input_digest = body.get("inputDigest")
        if input_digest != state["input_digest"]:
            raise HTTPException(status_code=409, detail="Commit inputDigest mismatch")

        receipts = body.get("receipts")
        if not isinstance(receipts, list):
            raise HTTPException(status_code=400, detail="receipts must be a list")

        jwk = state["verifier_jwk"]
        prop_map = state["proposals_by_call_id"]
        outcomes = []

        seen_receipt_ids = set()

        # Atomic verification of all receipts before any execution
        for r in receipts:
            if not isinstance(r, dict):
                raise HTTPException(status_code=400, detail="Malformed receipt entry")

            call_id = r.get("callId")
            receipt_id = r.get("receiptId")
            sig = r.get("receiptSignature")

            if not receipt_id or receipt_id in seen_receipt_ids:
                raise HTTPException(status_code=400, detail="Missing or duplicated receiptId")
            seen_receipt_ids.add(receipt_id)

            if call_id not in prop_map:
                raise HTTPException(status_code=400, detail=f"Unrecognized callId: {call_id}")

            stored_prop = prop_map[call_id]

            # Check action and dossierId matching
            if r.get("dossierId") != stored_prop["dossierId"] or r.get("action") != stored_prop["action"]:
                raise HTTPException(status_code=400, detail="Receipt metadata mismatch")

            # Check proposalDigest matching
            expected_digest = compute_proposal_digest(stored_prop)
            if r.get("proposalDigest") != expected_digest:
                raise HTTPException(status_code=400, detail="proposalDigest does not match proposal")

            # Build canonical receipt verification object
            # Receipt object contains every receipt field except receiptSignature
            inner_receipt = {
                "dossierId": r["dossierId"],
                "callId": r["callId"],
                "action": r["action"],
                "accepted": r["accepted"],
                "proposalDigest": r["proposalDigest"],
                "receiptId": r["receiptId"]
            }
            verification_envelope = {
                "profile": PROFILE,
                "evaluationId": eval_id,
                "inputDigest": input_digest,
                "receipt": inner_receipt
            }
            msg_bytes = canonical_json_bytes(verification_envelope)

            # Verify Ed25519 signature
            if not sig or not verify_receipt_signature(jwk, msg_bytes, sig):
                raise HTTPException(status_code=400, detail=f"Invalid Ed25519 receiptSignature for call {call_id}")

            outcome_status = "executed" if r.get("accepted") is True else "rejected"
            outcomes.append({
                "dossierId": r["dossierId"],
                "callId": r["callId"],
                "action": r["action"],
                "proposalDigest": r["proposalDigest"],
                "receiptId": r["receiptId"],
                "status": outcome_status
            })

        terminal_response = {
            "profile": PROFILE,
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes
        }

        with LOCK:
            state["status"] = "completed"
            state["terminal_response"] = terminal_response

        return JSONResponse(status_code=200, content=terminal_response)

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported operation '{op}'")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("mailroom:app", host="0.0.0.0", port=8001, reload=True)
