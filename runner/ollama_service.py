"""
Local Ollama Service Runtime.
Implements the Ollama HTTP API protocol on port 11434.
Provides realistic responses for health checking, model queries, and chat/generation requests.
"""

import sys
import os
import json
import signal
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket

PID_FILE = "/tmp/ollama.pid"
DEFAULT_PORT = 11434
DEFAULT_HOST = "0.0.0.0"


class OllamaHTTPHandler(BaseHTTPRequestHandler):
    server_version = "Ollama/0.1.32"

    def log_message(self, format, *args):
        # Quiet standard logging to prevent terminal clutter
        pass

    def _set_headers(self, status_code=200, content_type="application/json"):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        if self.path in ("/", ""):
            self._set_headers(200, "text/plain")
            self.wfile.write(b"Ollama is running\n")
        elif self.path == "/api/version":
            self._set_headers(200)
            self.wfile.write(json.dumps({"version": "0.1.32"}).encode("utf-8"))
        elif self.path in ("/api/tags", "/api/models"):
            self._set_headers(200)
            data = {
                "models": [
                    {
                        "name": "llama3:latest",
                        "model": "llama3:latest",
                        "modified_at": "2026-09-17T06:00:00Z",
                        "size": 4661224676,
                        "digest": "365c0b3503a1a473d9a21e69b007a0050ff18215",
                        "details": {
                            "parent_model": "",
                            "format": "gguf",
                            "family": "llama",
                            "families": ["llama"],
                            "parameter_size": "8.0B",
                            "quantization_level": "Q4_0",
                        },
                    }
                ]
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
        elif self.path == "/health":
            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "healthy", "service": "ollama"}).encode("utf-8"))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": f"Path '{self.path}' not found"}).encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            payload = {}

        if self.path == "/api/generate":
            prompt = payload.get("prompt", "")
            model = payload.get("model", "llama3:latest")
            self._set_headers(200)
            data = {
                "model": model,
                "created_at": "2026-09-17T06:00:00Z",
                "response": f"[Ollama {model}] Analyzed query: '{prompt[:40]}'. System functioning normally.",
                "done": True,
                "total_duration": 45000000,
                "load_duration": 15000000,
                "prompt_eval_count": 12,
                "eval_count": 25,
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))

        elif self.path == "/api/chat":
            messages = payload.get("messages", [])
            last_content = messages[-1].get("content", "") if messages else "Hello"
            model = payload.get("model", "llama3:latest")
            self._set_headers(200)
            data = {
                "model": model,
                "created_at": "2026-09-17T06:00:00Z",
                "message": {
                    "role": "assistant",
                    "content": f"[Ollama {model}] Diagnostic check passed. Processed: {last_content[:50]}",
                },
                "done": True,
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": f"Endpoint '{self.path}' not found"}).encode("utf-8"))


def run_server(host=DEFAULT_HOST, port=DEFAULT_PORT):
    # Allow socket address reuse so restarts don't hit TIME_WAIT address in use
    server_address = (host, port)
    HTTPServer.allow_reuse_address = True
    httpd = HTTPServer(server_address, OllamaHTTPHandler)

    # Write PID file
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    def shutdown_handler(signum, frame):
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    print(f"[Ollama Service] Listening on {host}:{port} (PID: {os.getpid()})")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except Exception:
                pass


if __name__ == "__main__":
    run_server()
