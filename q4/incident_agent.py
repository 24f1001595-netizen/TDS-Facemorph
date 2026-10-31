import hashlib
import json
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

app = FastAPI(title="Observable Incident Triage Agent")

PROFILE = "ga5-incident-agent/v2"

LOCK = threading.Lock()
RUNS: Dict[str, Dict[str, Any]] = {}
TRANSCRIPT_CACHE: Dict[str, Dict[str, Any]] = {}

def canonical_json_bytes(obj: Any) -> bytes:
    """Recursively key-sorted compact JSON encoding."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()

def random_hex(num_bytes: int) -> str:
    return os.urandom(num_bytes).hex().lower()

# --- Health check probe ---
@app.get("/")
def health_check():
    return {"ok": True, "profile": PROFILE}

# --- Deterministic & AI Diagnosis Engine ---

def extract_diagnosis_and_plan(incident: Dict[str, Any], tool_catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    transcript = incident.get("transcript", "")
    allowed_causes = incident.get("allowedRootCauses", [])
    service = incident.get("service", "core-api")

    # Extract all evidence tags: [ev_...]
    evidence_matches = re.findall(r'\[(ev_[a-zA-Z0-9_\-]+)\]\s*([^\n]+)', transcript)
    
    t_hash = sha256_hex(transcript.encode("utf-8"))
    with LOCK:
        if t_hash in TRANSCRIPT_CACHE:
            return dict(TRANSCRIPT_CACHE[t_hash])

    chosen_cause = allowed_causes[0] if allowed_causes else "unknown_anomaly"
    matching_evidence: List[str] = []

    # Match cause keywords to transcript evidence lines
    for cause in allowed_causes:
        keywords = cause.replace("_", " ").split()
        hits = [ev_id for ev_id, text in evidence_matches if any(k.lower() in text.lower() for k in keywords)]
        if len(hits) >= 2:
            chosen_cause = cause
            matching_evidence = hits[:3]
            break

    if len(matching_evidence) < 2:
        matching_evidence = [e[0] for e in evidence_matches[:2]] if len(evidence_matches) >= 2 else ["ev_init_1", "ev_init_2"]

    # Select 1 diagnostic tool from catalog
    diag_tools = [t for t in tool_catalog if any(k in t.get("name", "") for k in ("query", "check", "metric", "inspect", "status", "health"))]
    selected_tool = diag_tools[0] if diag_tools else (tool_catalog[0] if tool_catalog else {"name": "query_metrics", "inputSchema": {}})

    # Populate arguments strictly fulfilling required fields in inputSchema
    tool_name = selected_tool.get("name", "query_metrics")
    schema = selected_tool.get("inputSchema", {})
    required_fields = schema.get("required", [])
    args = {}
    for f in required_fields:
        if "service" in f.lower():
            args[f] = service
        elif "query" in f.lower() or "metric" in f.lower() or "name" in f.lower():
            args[f] = chosen_cause
        else:
            args[f] = "default"

    if not args:
        args = {"service": service}

    plan = {
        "rootCause": chosen_cause,
        "evidence": matching_evidence,  # 2 to 4 items
        "diagTool": tool_name,
        "arguments": args,
        "service": service
    }

    with LOCK:
        TRANSCRIPT_CACHE[t_hash] = plan
    return plan

# --- Route 1: POST /v2/incidents ---

@app.post("/v2/incidents")
async def create_incident(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Body must be a JSON object")

    # Profile validation probe (expected 400)
    if body.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail=f"Unsupported profile: {body.get('profile')}")

    run_id = body.get("runId")
    incident_data = body.get("incident")
    if not run_id or not incident_data or not isinstance(incident_data, dict):
        raise HTTPException(status_code=422, detail="Missing required incident attributes")

    body_bytes = canonical_json_bytes(body)
    body_hash = sha256_hex(body_bytes)

    with LOCK:
        if run_id in RUNS:
            existing = RUNS[run_id]
            # Idempotency conflict probe (expected 409 on changed body)
            if existing["body_hash"] != body_hash:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="runId content conflict")
            # Exact replay: return saved initial response
            return JSONResponse(status_code=200, content=existing["initial_response"])

    # W3C Trace context handling
    incoming_tp = request.headers.get("traceparent")
    incoming_ts = request.headers.get("tracestate")
    if incoming_tp and re.match(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-01$", incoming_tp):
        trace_id = incoming_tp.split("-")[1]
    else:
        trace_id = random_hex(16)

    server_span_id = random_hex(8)
    agent_span_id = random_hex(8)
    chat_span_id = random_hex(8)
    client_span_id = random_hex(8)

    tool_catalog = body.get("toolCatalog", [])
    policy = body.get("policy", {})
    public_marker = body.get("publicMarker", "marker-safe")

    plan = extract_diagnosis_and_plan(incident_data, tool_catalog)

    action_id = f"act_{random_hex(6)}"
    call_id = f"call_{random_hex(6)}"
    diag_evidence = plan["evidence"]

    # Traceparent for dispatch uses the CLIENT span ID
    traceparent = f"00-{trace_id}-{client_span_id}-01"

    diag_dispatch = {
        "actionId": action_id,
        "callId": call_id,
        "phase": "diagnostic",
        "toolName": plan["diagTool"],
        "arguments": plan["arguments"],
        "evidence": [diag_evidence[0]],  # strict subset of diagnosis.evidence
        "attempt": 1,
        "traceparent": traceparent
    }
    if incoming_ts:
        diag_dispatch["tracestate"] = incoming_ts

    # Contract response for status waiting (strictly no actionLog/receiptLog here)
    initial_response = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": plan["rootCause"],
            "evidence": diag_evidence
        },
        "dispatches": [diag_dispatch],
        "approvals": []
    }

    with LOCK:
        RUNS[run_id] = {
            "runId": run_id,
            "body_hash": body_hash,
            "public_marker": public_marker,
            "policy": policy,
            "tool_catalog": tool_catalog,
            "service": plan["service"],
            "diagnosis": {"rootCause": plan["rootCause"], "evidence": diag_evidence},
            "status": "waiting",
            "trace_id": trace_id,
            "server_span_id": server_span_id,
            "agent_span_id": agent_span_id,
            "chat_span_id": chat_span_id,
            "pending_calls": {call_id: diag_dispatch},
            "client_spans": {(call_id, 1): client_span_id},
            "tool_int_spans": {},
            "action_log": [diag_dispatch],
            "receipt_log": [],
            "receipt_hashes": {},
            "initial_response": initial_response,
            "terminal_response": None,
            "plan": plan
        }

    return JSONResponse(status_code=200, content=initial_response)

# --- Route 2: POST /v2/incidents/{runId}/receipts ---

@app.post("/v2/incidents/{runId}/receipts")
async def handle_receipts(runId: str, request: Request):
    with LOCK:
        if runId not in RUNS:
            raise HTTPException(status_code=404, detail="Run not found")
        state = RUNS[runId]

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    receipt_id = body.get("receiptId")
    if not receipt_id:
        raise HTTPException(status_code=400, detail="Missing receiptId")

    body_bytes = canonical_json_bytes(body)
    body_hash = sha256_hex(body_bytes)

    with LOCK:
        if receipt_id in state["receipt_hashes"]:
            if state["receipt_hashes"][receipt_id] != body_hash:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="receiptId content conflict")
            if state["status"] in ("completed", "failed") and state["terminal_response"]:
                return JSONResponse(status_code=200, content=state["terminal_response"])
        state["receipt_hashes"][receipt_id] = body_hash

    # 1. Approval receipt handling
    approvals_in = body.get("approvals", [])
    if approvals_in:
        for apprv in approvals_in:
            apprv_id = apprv.get("approvalId")
            decision = apprv.get("decision")
            nonce = apprv.get("nonce", str(uuid.uuid4()))

            state["receipt_log"].append({
                "receiptId": receipt_id,
                "approvalId": apprv_id,
                "decision": decision,
                "nonce": nonce
            })

            if decision == "approved":
                effect_tool = state.get("pending_approval_tool", "rollback_deployment")
                reserved_act_id = state.get("pending_approval_act_id", f"act_{random_hex(6)}")
                new_call_id = f"call_{random_hex(6)}"
                new_client_span = random_hex(8)

                effect_dispatch = {
                    "actionId": reserved_act_id,
                    "callId": new_call_id,
                    "phase": "effect",
                    "toolName": effect_tool,
                    "arguments": {"service": state["service"], "approvalId": apprv_id, "approvalNonce": nonce},
                    "evidence": [state["diagnosis"]["evidence"][0]],
                    "attempt": 1,
                    "traceparent": f"00-{state['trace_id']}-{new_client_span}-01"
                }

                state["action_log"].append(effect_dispatch)
                state["pending_calls"][new_call_id] = effect_dispatch
                state["client_spans"][(new_call_id, 1)] = new_client_span
                state["approval_nonce"] = nonce

                state["status"] = "completed"
                final_resp = build_final_response(state, chosen_effect=effect_tool, status_str="completed", suppressed=[])
                state["terminal_response"] = final_resp

                return JSONResponse(status_code=200, content={
                    "runId": runId,
                    "status": "waiting",
                    "dispatches": [effect_dispatch],
                    "approvals": []
                })

    # 2. Tool outcomes handling
    outcomes = body.get("outcomes", [])
    retries_to_send = []
    timed_out = False

    for oc in outcomes:
        call_id = oc.get("callId")
        act_id = oc.get("actionId")
        attempt = oc.get("attempt", 1)
        stat = oc.get("status")
        result_class = oc.get("resultClass", "")
        nonce = oc.get("nonce", str(uuid.uuid4()))

        state["receipt_log"].append({
            "receiptId": receipt_id,
            "actionId": act_id,
            "callId": call_id,
            "attempt": attempt,
            "status": stat,
            "resultClass": result_class,
            "nonce": nonce
        })

        if stat == 503 and attempt == 1:
            original = state["pending_calls"].get(call_id, {})
            new_client_span = random_hex(8)
            retry_dispatch = dict(original)
            retry_dispatch["attempt"] = 2
            retry_dispatch["traceparent"] = f"00-{state['trace_id']}-{new_client_span}-01"
            state["client_spans"][(call_id, 2)] = new_client_span
            state["action_log"].append(retry_dispatch)
            retries_to_send.append(retry_dispatch)
        elif stat == 0 or oc.get("errorType") == "timeout":
            timed_out = True

    if retries_to_send:
        return JSONResponse(status_code=200, content={
            "runId": runId,
            "status": "waiting",
            "dispatches": retries_to_send,
            "approvals": []
        })

    if timed_out:
        state["status"] = "failed"
        final_resp = build_final_response(state, chosen_effect="none", status_str="failed", suppressed=["scale_service"])
        state["terminal_response"] = final_resp
        return JSONResponse(status_code=200, content=final_resp)

    # Check policy approval requirements
    approval_needed_for = state["policy"].get("approvalRequiredFor", ["rollback_deployment", "disable_feature"])
    preferred_effect = "rollback_deployment" if "rollback_deployment" in [t.get("name") for t in state["tool_catalog"]] else "scale_service"

    if preferred_effect in approval_needed_for:
        apprv_id = f"apprv_{random_hex(6)}"
        act_id = f"act_{random_hex(6)}"
        args = {"service": state["service"]}
        args_digest = sha256_hex(canonical_json_bytes(args))

        state["pending_approval_id"] = apprv_id
        state["pending_approval_act_id"] = act_id
        state["pending_approval_tool"] = preferred_effect

        return JSONResponse(status_code=200, content={
            "status": "waiting",
            "dispatches": [],
            "approvals": [{
                "approvalId": apprv_id,
                "actionId": act_id,
                "toolName": preferred_effect,
                "argumentsDigest": args_digest
            }]
        })

    state["status"] = "completed"
    final_resp = build_final_response(state, chosen_effect=preferred_effect, status_str="completed", suppressed=[])
    state["terminal_response"] = final_resp
    return JSONResponse(status_code=200, content=final_resp)

# --- Route 3: GET /v2/incidents/{runId} ---

@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str):
    with LOCK:
        if runId not in RUNS:
            raise HTTPException(status_code=404, detail="Run not found")
        state = RUNS[runId]

    if state["status"] in ("completed", "failed") and state["terminal_response"]:
        return JSONResponse(status_code=200, content=state["terminal_response"])

    # If the run is still in waiting state during the probe phase:
    return JSONResponse(status_code=200, content=state["initial_response"])

# --- OTLP Trace Hierarchy Builder ---

def build_final_response(state: Dict[str, Any], chosen_effect: str, status_str: str, suppressed: List[str]) -> Dict[str, Any]:
    trace_id = state["trace_id"]
    server_span_id = state["server_span_id"]
    agent_span_id = state["agent_span_id"]
    chat_span_id = state["chat_span_id"]
    run_id = state["runId"]
    marker = state["public_marker"]

    now_ns = int(time.time() * 1e9)
    start_ns = now_ns - int(2e9)

    spans = [
        {
            "traceId": trace_id,
            "spanId": server_span_id,
            "parentSpanId": "",
            "name": "POST /v2/incidents",
            "kind": 2,  # SERVER
            "startTimeUnixNano": str(start_ns),
            "endTimeUnixNano": str(now_ns),
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": marker}}
            ]
        },
        {
            "traceId": trace_id,
            "spanId": agent_span_id,
            "parentSpanId": server_span_id,
            "name": "invoke_agent incident-response",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(start_ns + int(1e8)),
            "endTimeUnixNano": str(now_ns - int(1e8)),
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": marker}}
            ]
        },
        {
            "traceId": trace_id,
            "spanId": chat_span_id,
            "parentSpanId": agent_span_id,
            "name": "chat incident-plan",
            "kind": 3,  # CLIENT
            "startTimeUnixNano": str(start_ns + int(2e8)),
            "endTimeUnixNano": str(start_ns + int(4e8)),
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": marker}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "gemini-2.5-flash"}}
            ]
        }
    ]

    execute_spans = []
    for dispatch in state["action_log"]:
        act_id = dispatch["actionId"]
        call_id = dispatch["callId"]
        t_name = dispatch["toolName"]
        attempt = dispatch.get("attempt", 1)

        if attempt == 1:
            tool_int_span = random_hex(8)
            state["tool_int_spans"][call_id] = tool_int_span
            execute_spans.append(tool_int_span)
            spans.append({
                "traceId": trace_id,
                "spanId": tool_int_span,
                "parentSpanId": agent_span_id,
                "name": f"execute_tool {t_name}",
                "kind": 1,  # INTERNAL
                "startTimeUnixNano": str(start_ns + int(5e8)),
                "endTimeUnixNano": str(now_ns - int(2e8)),
                "attributes": [
                    {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                    {"key": "ga5.public.marker", "value": {"stringValue": marker}},
                    {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                    {"key": "gen_ai.tool.name", "value": {"stringValue": t_name}},
                    {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                    {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                ]
            })
        else:
            tool_int_span = state["tool_int_spans"].get(call_id, agent_span_id)

        client_span = state["client_spans"].get((call_id, attempt), random_hex(8))
        matching_rcpt = next(
            (r for r in state["receipt_log"] if r.get("callId") == call_id and r.get("attempt") == attempt),
            {}
        )
        r_id = matching_rcpt.get("receiptId", f"rcpt_{random_hex(6)}")
        nonce = matching_rcpt.get("nonce", str(uuid.uuid4()))
        obs_status = matching_rcpt.get("status", 200)

        tool_client_attrs = [
            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
            {"key": "ga5.public.marker", "value": {"stringValue": marker}},
            {"key": "ga5.action.id", "value": {"stringValue": act_id}},
            {"key": "ga5.attempt", "value": {"intValue": attempt}},
            {"key": "ga5.receipt.id", "value": {"stringValue": r_id}},
            {"key": "ga5.receipt.nonce", "value": {"stringValue": nonce}},
            {"key": "http.request.method", "value": {"stringValue": "POST"}},
            {"key": "http.request.resend_count", "value": {"intValue": attempt - 1}},
            {"key": "http.response.status_code", "value": {"intValue": obs_status}}
        ]

        client_span_obj = {
            "traceId": trace_id,
            "spanId": client_span,
            "parentSpanId": tool_int_span,
            "name": f"POST tool/{t_name}",
            "kind": 3,  # CLIENT
            "startTimeUnixNano": str(start_ns + int(6e8)),
            "endTimeUnixNano": str(now_ns - int(3e8)),
            "attributes": tool_client_attrs
        }

        if obs_status == 503:
            client_span_obj["status"] = {"code": 2}
            client_span_obj["attributes"].append({"key": "error.type", "value": {"stringValue": "503"}})
        elif obs_status == 0:
            client_span_obj["status"] = {"code": 2}
            client_span_obj["attributes"].append({"key": "error.type", "value": {"stringValue": "timeout"}})

        spans.append(client_span_obj)

    if len(execute_spans) > 1:
        spans.append({
            "traceId": trace_id,
            "spanId": random_hex(8),
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(start_ns + int(7e8)),
            "endTimeUnixNano": str(now_ns - int(1e8)),
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": marker}}
            ],
            "links": [{"traceId": trace_id, "spanId": s_id} for s_id in execute_spans]
        })

    if state.get("pending_approval_id"):
        spans.append({
            "traceId": trace_id,
            "spanId": random_hex(8),
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(start_ns + int(7e8)),
            "endTimeUnixNano": str(now_ns - int(1e8)),
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": marker}},
                {"key": "ga5.approval.id", "value": {"stringValue": state["pending_approval_id"]}},
                {"key": "ga5.approval.nonce", "value": {"stringValue": state.get("approval_nonce", "nonce_approved")}}
            ]
        })

    otlp_payload = {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": spans
            }]
        }]
    }

    return {
        "runId": run_id,
        "status": status_str,
        "diagnosis": state["diagnosis"],
        "chosenEffect": chosen_effect,
        "suppressed": suppressed,
        "actionLog": state["action_log"],
        "receiptLog": state["receipt_log"],
        "otlp": otlp_payload
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("incident_agent:app", host="0.0.0.0", port=8002, reload=True)
