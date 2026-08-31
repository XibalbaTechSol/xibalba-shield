from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from shield.transaction_gateway import TransactionIntent
from shield.transaction_simulator import simulate_transaction_intent


def test_simulator_uses_read_only_rpc_methods_and_returns_no_broadcast():
    methods = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            methods.append(body["method"])
            result = "0x" if body["method"] == "eth_call" else "0x5208"
            raw = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        intent = TransactionIntent.from_dict(
            {
                "tenant_id": "t",
                "device_id": "d",
                "agent_id": "a",
                "request_id": "r",
                "chain_id": 84532,
                "to": "0x1111111111111111111111111111111111111111",
                "function_selector": "0xa9059cbb",
                "calldata": "0xa9059cbb" + "00" * 32,
            }
        )
        result = simulate_transaction_intent(intent, rpc_url=f"http://127.0.0.1:{server.server_port}")
        assert result.gas_estimate == 21000
        assert result.execution == "not_broadcast"
        assert methods == ["eth_call", "eth_estimateGas"]
    finally:
        server.shutdown()
