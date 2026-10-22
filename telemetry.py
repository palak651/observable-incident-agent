
import secrets
import time
import re


def make_hex(length):
    while True:
        value = secrets.token_hex(length // 2)
        if int(value, 16) != 0:
            return value


def now_ns():
    return str(time.time_ns())


def attr(key, value):
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


class Trace:
    def __init__(self, run_id, marker, incoming=None, tracestate=None):
        self.run_id = run_id
        self.marker = marker
        self.tracestate = tracestate
        self.spans = []
        self.tool_spans = {}
        self.client_spans = {}

        parts = (incoming or "").split("-")
        valid = (
            len(parts) == 4
            and parts[0] == "00"
            and re.fullmatch(r"[0-9a-f]{32}", parts[1])
            and int(parts[1], 16) != 0
            and re.fullmatch(r"[0-9a-f]{16}", parts[2])
            and int(parts[2], 16) != 0
        )

        self.trace_id = parts[1] if valid else make_hex(32)
        parent = parts[2] if valid else None

        self.server = self.add(
            "POST /v2/incidents", 2, parent, []
        )
        self.agent = self.add(
            "invoke_agent incident-response", 1,
            self.server["spanId"], []
        )

    def add(self, name, kind, parent=None, extra=None, links=None):
        start = now_ns()
        span = {
            "traceId": self.trace_id,
            "spanId": make_hex(16),
            "name": name,
            "kind": kind,
            "startTimeUnixNano": start,
            "endTimeUnixNano": now_ns(),
            "attributes": [
                attr("ga5.run.id", self.run_id),
                attr("ga5.public.marker", self.marker),
            ] + (extra or []),
            "events": [],
            "links": links or [],
            "status": {"code": 0},
        }
        if parent:
            span["parentSpanId"] = parent
        self.spans.append(span)
        return span

    def add_model(self, model):
        self.add(
            "chat incident-plan", 3, self.agent["spanId"],
            [
                attr("gen_ai.operation.name", "chat"),
                attr("gen_ai.request.model", model),
            ],
        )

    def dispatch(self, tool, action_id, call_id, attempt):
        if action_id not in self.tool_spans:
            self.tool_spans[action_id] = self.add(
                "execute_tool " + tool, 1, self.agent["spanId"],
                [
                    attr("ga5.action.id", action_id),
                    attr("gen_ai.tool.name", tool),
                    attr("gen_ai.tool.call.id", call_id),
                    attr("gen_ai.operation.name", "execute_tool"),
                ],
            )

        client = self.add(
            "POST tool/" + tool, 3,
            self.tool_spans[action_id]["spanId"],
            [
                attr("ga5.action.id", action_id),
                attr("ga5.attempt", attempt),
                attr("http.request.method", "POST"),
                attr("http.request.resend_count", attempt - 1),
            ],
        )
        self.client_spans[client["spanId"]] = client
        return client["spanId"]

    def receipt(self, span_id, receipt_id, nonce, status, error_type=None):
        span = self.client_spans[span_id]
        span["attributes"].extend([
            attr("ga5.receipt.id", receipt_id),
            attr("ga5.receipt.nonce", nonce),
            attr("http.response.status_code", int(status)),
        ])

        if error_type:
            span["attributes"].append(attr("error.type", error_type))
            span["status"] = {"code": 2}
        elif int(status) == 503 or int(status) == 0:
            span["status"] = {"code": 2}
            if int(status) == 503:
                span["attributes"].append(attr("error.type", "503"))
        else:
            span["status"] = {"code": 1 if 200 <= int(status) < 300 else 2}
        span["endTimeUnixNano"] = now_ns()

    def add_join(self, action_ids):
        links = []
        for action_id in action_ids:
            span = self.tool_spans.get(action_id)
            if span:
                links.append({
                    "traceId": self.trace_id,
                    "spanId": span["spanId"],
                    "attributes": [],
                })
        self.add("incident.join", 1, self.agent["spanId"], links=links)

    def add_approval(self, approval_id, nonce=None):
        values = [attr("ga5.approval.id", approval_id)]
        if nonce:
            values.append(attr("ga5.approval.receipt.nonce", nonce))
        self.add("approval_gate", 1, self.agent["spanId"], values)

    def export(self):
        return {
            "resourceSpans": [{
                "resource": {
                    "attributes": [attr("service.name", "incident-agent")]
                },
                "scopeSpans": [{
                    "scope": {"name": "incident-agent"},
                    "spans": self.spans,
                }],
            }]
        }

    def to_dict(self):
        return {
            "run_id": self.run_id,
            "marker": self.marker,
            "trace_id": self.trace_id,
            "tracestate": self.tracestate,
            "spans": self.spans,
            "tool_spans": self.tool_spans,
            "client_spans": self.client_spans,
            "server": self.server,
            "agent": self.agent,
        }
