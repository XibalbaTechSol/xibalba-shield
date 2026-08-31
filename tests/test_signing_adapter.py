from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from shield.signing_adapter import ExternalWalletSigner


def test_external_signer_receives_approved_intent_but_no_private_key():
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.update(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            raw = json.dumps({"raw_transaction": "0xdeadbeef", "transaction_hash": "0xtx"}).encode()
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
        signed = ExternalWalletSigner(f"http://127.0.0.1:{server.server_port}").sign(
            consumed_approval={
                "approval_id": "approval-1", "intent_hash": "sha256:abc", "consumed_at": "2099-01-01T00:00:00Z",
                "intent": {"request_id": "req-1"},
            },
            unsigned_transaction={"to": "0x1111", "data": "0x"},
        )
        assert signed.raw_transaction == "0xdeadbeef"
        assert received["approval_id"] == "approval-1"
        assert "private_key" not in received
    finally:
        server.shutdown()
