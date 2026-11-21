import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from shield.agent_core.tier3_http_backend import HttpTier3Backend
from shield.schemas.events import Activity, Decision, EscalationRequest, ProcessActivity, ProcessInfo

def req():
    return EscalationRequest(ProcessActivity("d", ProcessInfo(1, "x"), Activity("exec")), Decision("escalate"), Decision("escalate"))

def server(payload, status=200):
    captured=[]
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            captured.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            self.send_response(status); self.end_headers(); self.wfile.write(raw)
        def log_message(self, *args): pass
    s=ThreadingHTTPServer(("127.0.0.1",0),H); threading.Thread(target=s.serve_forever,daemon=True).start()
    return s, f"http://127.0.0.1:{s.server_port}", captured

def test_well_formed_response():
    s,u,_=server({"verdict":"release","reason":"ok"})
    try: assert HttpTier3Backend(u).adjudicate(req()).verdict == "release"
    finally: s.shutdown()

def test_payload_is_bounded_evidence():
    s,u,c=server({"verdict":"uncertain"}); r=req(); r.event.tool_input="secret-value"
    try:
        HttpTier3Backend(u).adjudicate(r); assert "secret-value" not in json.dumps(c[0])
    finally: s.shutdown()

def test_prose_non_json_and_http_error_are_uncertain():
    for payload,status in [({"verdict":"sure"},200),(b"not json",200),({"verdict":"release"},500)]:
        s,u,_=server(payload,status)
        try: assert HttpTier3Backend(u).adjudicate(req()).verdict == "uncertain"
        finally: s.shutdown()

def test_connection_failure_is_uncertain():
    assert HttpTier3Backend("http://127.0.0.1:1", timeout_seconds=.1).adjudicate(req()).verdict == "uncertain"
