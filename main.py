
import os
import json
import re
import uuid
import hashlib

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from planner import make_plan
from state import Store
from telemetry import Trace, attr

PROFILE = "ga5-incident-agent/v2"
DB_PATH = os.getenv("DATABASE_PATH", "./incident.db")

app = FastAPI(title="Observable Incident Triage Agent")
store = Store(DB_PATH)


def new_id(prefix):
    return prefix + "_" + uuid.uuid4().hex


def digest(value):
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def valid_id(value):
    return isinstance(value, str) and len(value) >= 8


def load_trace(data):
    trace = Trace.__new__(Trace)
    trace.run_id = data["run_id"]
    trace.marker = data["marker"]
    trace.trace_id = data["trace_id"]
    trace.tracestate = data.get("tracestate")
    trace.spans = data["spans"]

    by_id = {s["spanId"]: s for s in trace.spans}
    trace.server = next(
        s for s in trace.spans if s["name"] == "POST /v2/incidents"
    )
    trace.agent = next(
        s for s in trace.spans if s["name"].startswith("invoke_agent ")
    )

    trace.tool_spans = {
        s["attributes"][0]["value"]["stringValue"]: s
        for s in trace.spans
        if s["name"].startswith("execute_tool ")
        and any(a["key"] == "ga5.action.id" for a in s["attributes"])
    }
    trace.client_spans = {
        s["spanId"]: s for s in trace.spans
        if s["name"].startswith("POST tool/")
    }
    return trace


def hydrate(state):
    state["trace"] = load_trace(state["trace"])
    return state


def persist(run_id, state):
    saved = dict(state)
    saved["trace"] = state["trace"].to_dict()
    store.save_state(run_id, saved)


def public_state(state):
    result = state["public"]
    result["otlp"] = state["trace"].export()
    result["actionLog"] = state["action_log"]
    result["receiptLog"] = state["receipt_log"]
    return result


def response(state):
    return JSONResponse(
        json.loads(json.dumps(public_state(state)))
    )


def catalog_tool(state, name):
    for tool in state["catalog"]:
        if tool.get("name") == name:
            return tool
    return None


def requires_approval(state, tool):
    return tool in state["policy"].get("approvalRequiredFor", [])


def add_dispatch(state, tool, arguments, phase, evidence,
                 action_id=None, call_id=None, attempt=1,
                 approval_id=None, approval_nonce=None):
    action_id = action_id or new_id("action")
    call_id = call_id or new_id("call")

    client_span_id = state["trace"].dispatch(
        tool, action_id, call_id, attempt
    )

    item = {
        "actionId": action_id,
        "callId": call_id,
        "phase": phase,
        "toolName": tool,
        "arguments": arguments,
        "evidence": evidence,
        "attempt": attempt,
        "traceparent": (
            "00-" + state["trace"].trace_id + "-"
            + client_span_id + "-01"
        ),
    }
    if approval_id:
        item["approvalId"] = approval_id
        item["approvalNonce"] = approval_nonce

    state["action_log"].append(item)
    state["pending"].append({
        **item,
        "clientSpanId": client_span_id,
    })
    state["public"]["dispatches"].append(item)
    return item


def update_public(state):
    pending_keys = {
        (p["actionId"], p["attempt"]) for p in state["pending"]
    }
    state["public"]["dispatches"] = [
        a for a in state["action_log"]
        if (a["actionId"], a["attempt"]) in pending_keys
    ]
    state["public"]["actionLog"] = state["action_log"]
    state["public"]["receiptLog"] = state["receipt_log"]
    state["public"]["suppressed"] = state["suppressed"]
    state["public"]["otlp"] = state["trace"].export()


def finalise(state, status):
    state["public"]["status"] = status
    state["public"]["dispatches"] = []
    state["public"]["approvals"] = []
    state["public"]["chosenEffect"] = state["chosen_effect"]
    update_public(state)


def plan_effect(state):
    if state["diagnostic_failed"]:
        state["suppressed"].append({
            "reason": "diagnostic_failed",
            "toolName": (
                state["effect"].get("toolName")
                if state["effect"] else None
            ),
        })
        finalise(state, "failed")
        return

    if not state["effect"]:
        finalise(state, "failed")
        return

    effect = state["effect"]
    tool = effect["toolName"]
    arguments = effect.get("arguments", {})
    action_id = new_id("action")

    if requires_approval(state, tool):
        approval = {
            "approvalId": new_id("approval"),
            "actionId": action_id,
            "toolName": tool,
            "argumentsDigest": digest(arguments),
        }
        state["waiting_approval"] = {
            **approval, "arguments": arguments,
        }
        state["trace"].add_approval(approval["approvalId"])
        state["public"]["approvals"] = [approval]
        state["public"]["dispatches"] = []
        state["public"]["status"] = "waiting"
        update_public(state)
        return

    state["chosen_effect"] = tool
    add_dispatch(
        state, tool, arguments, "effect",
        state["public"]["diagnosis"]["evidence"],
        action_id=action_id,
    )
    state["public"]["status"] = "waiting"
    update_public(state)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v2/incidents")
async def create_incident(request: Request):
    body = await request.json()

    if not isinstance(body, dict):
        raise HTTPException(400, "JSON object required")
    if body.get("profile") != PROFILE:
        raise HTTPException(422, "Unsupported profile")
    run_id = body.get("runId")
    if not valid_id(run_id):
        raise HTTPException(422, "Invalid runId")
    if not isinstance(body.get("incident"), dict):
        raise HTTPException(422, "Invalid incident")
    if not isinstance(body.get("toolCatalog"), list):
        raise HTTPException(422, "Invalid toolCatalog")
    if not isinstance(body.get("policy"), dict):
        raise HTTPException(422, "Invalid policy")

    request_hash = digest(body)
    existing = store.get_run(run_id)

    if existing:
        if existing["request_hash"] != request_hash:
            raise HTTPException(409, "runId content conflict")
        return response(hydrate(existing["state"]))

    # make_plan intentionally receives no sensitive field.
    try:
        plan = await make_plan({
            "incident": body["incident"],
            "toolCatalog": body["toolCatalog"],
            "policy": body["policy"],
            "agentName": body.get("agentName", "incident-response"),
        })
    except Exception:
        raise HTTPException(502, "Planning failed")

    incident = body["incident"]
    policy = body["policy"]
    catalog = body["toolCatalog"]
    transcript = incident.get("transcript", "")
    evidence_ids = re.findall(r"\[([^\]]+)\]", transcript)

    root = plan.get("rootCause")
    evidence = plan.get("evidence")
    if root not in incident.get("allowedRootCauses", []):
        raise HTTPException(422, "Invalid root cause")
    if not isinstance(evidence, list) or not 2 <= len(evidence) <= 4:
        raise HTTPException(422, "Invalid evidence list")
    if len(set(evidence)) != len(evidence):
        raise HTTPException(422, "Duplicate evidence")
    if any(e not in evidence_ids for e in evidence):
        raise HTTPException(422, "Unknown evidence ID")

    effect_tools = set(policy.get("effectTools", []))
    max_diagnostics = min(
        3, max(1, int(policy.get("maximumDiagnostics", 3)))
    )
    diagnostics = []
    seen = set()

    for item in plan.get("diagnostics", []):
        if not isinstance(item, dict):
            continue
        name = item.get("toolName")
        args = item.get("arguments", {})
        if (
            name in seen or name in effect_tools
            or not catalog_tool(
                {"catalog": catalog}, name
            )
            or not isinstance(args, dict)
        ):
            continue
        diagnostics.append((name, args))
        seen.add(name)
        if len(diagnostics) == max_diagnostics:
            break

    if not diagnostics:
        raise HTTPException(422, "No valid diagnostic tools selected")

    effect = plan.get("effect")
    if (
        not isinstance(effect, dict)
        or effect.get("toolName") not in effect_tools
        or not catalog_tool({"catalog": catalog}, effect.get("toolName"))
        or not isinstance(effect.get("arguments", {}), dict)
    ):
        effect = None

    trace = Trace(
        run_id,
        str(body.get("publicMarker", "public")),
        request.headers.get("traceparent"),
        request.headers.get("tracestate"),
    )
    trace.add_model(os.getenv("MODEL_NAME", "gpt-4o-mini"))

    state = {
        "catalog": catalog,
        "policy": policy,
        "effect": effect,
        "pending": [],
        "waiting_approval": None,
        "diagnostic_failed": False,
        "diagnostics_complete": False,
        "chosen_effect": None,
        "suppressed": [],
        "action_log": [],
        "receipt_log": [],
        "receipt_hashes": {},
        "trace": trace,
        "public": {
            "runId": run_id,
            "status": "waiting",
            "diagnosis": {
                "rootCause": root,
                "evidence": evidence,
            },
            "dispatches": [],
            "approvals": [],
            "actionLog": [],
            "receiptLog": [],
            "chosenEffect": None,
            "suppressed": [],
        },
    }

    for name, args in diagnostics:
        add_dispatch(
            state, name, args, "diagnostic", [evidence[0]]
        )

    if len(diagnostics) > 1:
        trace.add_join([
            p["actionId"] for p in state["pending"]
        ])

    update_public(state)
    store.put_run(run_id, request_hash, {
        **state,
        "trace": trace.to_dict(),
    })
    return response(state)


@app.post("/v2/incidents/{run_id}/receipts")
async def receive_receipt(run_id: str, request: Request):
    body = await request.json()
    if not isinstance(body, dict) or not valid_id(body.get("receiptId")):
        raise HTTPException(422, "Invalid receipt")

    row = store.get_run(run_id)
    if not row:
        raise HTTPException(404, "Unknown runId")

    state = hydrate(row["state"])
    receipt_id = body["receiptId"]
    receipt_hash = digest(body)

    if receipt_id in state["receipt_hashes"]:
        if state["receipt_hashes"][receipt_id] != receipt_hash:
            raise HTTPException(409, "receiptId content conflict")
        return response(state)

    outcomes = body.get("outcomes", [])
    approvals = body.get("approvals", [])
    if not isinstance(outcomes, list) or not isinstance(approvals, list):
        raise HTTPException(422, "Receipt arrays required")
    if outcomes and approvals:
        raise HTTPException(422, "Use outcomes or approvals, not both")

    # Validate the entire receipt before changing state.
    matched = []
    for outcome in outcomes:
        pending = next((
            p for p in state["pending"]
            if p["actionId"] == outcome.get("actionId")
            and p["callId"] == outcome.get("callId")
            and p["attempt"] == outcome.get("attempt")
        ), None)
        if pending is None:
            raise HTTPException(422, "Outcome is not pending")
        matched.append((pending, outcome))

    pending_approval = state["waiting_approval"]
    for approval in approvals:
        if (
            not pending_approval
            or approval.get("approvalId") != pending_approval["approvalId"]
            or approval.get("decision") not in ("approved", "denied")
        ):
            raise HTTPException(422, "Invalid approval receipt")

    state["receipt_hashes"][receipt_id] = receipt_hash

    for pending, outcome in matched:
        state["pending"].remove(pending)
        status = outcome.get("status")
        nonce = outcome.get("nonce")
        error_type = outcome.get("errorType")

        state["receipt_log"].append({
            "receiptId": receipt_id,
            "actionId": pending["actionId"],
            "callId": pending["callId"],
            "attempt": pending["attempt"],
            "status": status,
            "resultClass": outcome.get("resultClass"),
            "nonce": nonce,
        })

        state["trace"].receipt(
            pending["clientSpanId"], receipt_id, nonce,
            status, error_type,
        )

        if pending["phase"] == "diagnostic":
            if status == 503 and pending["attempt"] == 1:
                add_dispatch(
                    state, pending["toolName"], pending["arguments"],
                    "diagnostic", pending["evidence"],
                    action_id=pending["actionId"],
                    call_id=pending["callId"], attempt=2,
                )
            elif status == 0 and error_type == "timeout":
                state["diagnostic_failed"] = True
            elif not isinstance(status, int) or not 200 <= status < 300:
                state["diagnostic_failed"] = True
        else:
            if not isinstance(status, int) or not 200 <= status < 300:
                state["diagnostic_failed"] = True

    for approval in approvals:
        pending = state["waiting_approval"]
        nonce = approval.get("nonce")
        state["receipt_log"].append({
            "receiptId": receipt_id,
            "approvalId": pending["approvalId"],
            "decision": approval["decision"],
            "nonce": nonce,
        })
        state["trace"].add_approval(pending["approvalId"], nonce)
        state["waiting_approval"] = None

        if approval["decision"] == "approved":
            state["chosen_effect"] = pending["toolName"]
            add_dispatch(
                state, pending["toolName"], pending["arguments"],
                "effect", state["public"]["diagnosis"]["evidence"],
                action_id=pending["actionId"],
                approval_id=pending["approvalId"],
                approval_nonce=nonce,
            )
        else:
            state["suppressed"].append({
                "toolName": pending["toolName"],
                "reason": "approval_denied",
            })
            state["diagnostic_failed"] = True

    # Continue only after all diagnostic calls have succeeded.
    if not state["pending"] and not state["waiting_approval"]:
        if state["diagnostic_failed"]:
            if any(a["phase"] == "diagnostic" for a in state["action_log"]):
                state["suppressed"].append({
                    "reason": "diagnostic_failed",
                    "toolName": (
                        state["effect"]["toolName"]
                        if state["effect"] else None
                    ),
                })
            finalise(state, "failed")
        else:
            diagnostics = [
                a for a in state["action_log"]
                if a["phase"] == "diagnostic"
            ]
            diagnostic_receipts = [
                r for r in state["receipt_log"] if "callId" in r
            ]
            latest = {}
            for item in diagnostic_receipts:
                latest[item["callId"]] = item

            done = bool(diagnostics) and all(
                a["callId"] in latest
                and isinstance(latest[a["callId"]]["status"], int)
                and 200 <= latest[a["callId"]]["status"] < 300
                for a in diagnostics
            )
            if done and not state["chosen_effect"]:
                plan_effect(state)
            elif state["chosen_effect"] and not state["pending"]:
                finalise(state, "completed")

    update_public(state)
    persist(run_id, state)
    return response(state)


@app.get("/v2/incidents/{run_id}")
def get_incident(run_id: str):
    row = store.get_run(run_id)
    if not row:
        raise HTTPException(404, "Unknown runId")
    return response(hydrate(row["state"]))
