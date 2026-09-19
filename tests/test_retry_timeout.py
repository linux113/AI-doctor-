"""Regression tests for retry_request timing."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from runner.remediation import retry_request


class _SlowSuccessHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        time.sleep(6)
        body = json.dumps({"status": "ok"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_retry_request_allows_realistic_ollama_response_time():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SlowSuccessHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = retry_request(
            url=f"http://127.0.0.1:{server.server_port}/api/generate",
            method="POST",
            payload={"prompt": "test"},
        )
        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["response"] == {"status": "ok"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
