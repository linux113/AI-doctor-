"""
Shared fixtures for the AI Doctor test suite.

Real Ollama vs. generic helpers
-------------------------------
Two categories of test live in this suite and they must not be confused:

1. **Ollama lifecycle tests** - start, stop, detect, recover, heal to RESOLVED.
   These require the REAL `ollama` binary and a REAL daemon. When Ollama is not
   installed they SKIP with an explicit reason. They are never satisfied by a
   substitute: a Python HTTP server listening on 11434 is not Ollama, and a test
   that accepted one would be asserting nothing about the product. Use the
   `requires_real_ollama` fixture.

2. **Generic utility tests** - `check_port` (a TCP connect), `retry_request`
   (an HTTP client with SSRF validation), allowlist enforcement, timeline
   attribution, secret redaction. These have no Ollama dependency at all and
   must run everywhere. Where they need a listener they use `local_http_server`,
   which binds an EPHEMERAL port, serves a fixed JSON document, and is never
   described as Ollama - it exercises the transport utility, not the runtime.

Nothing in this file starts, stops or impersonates Ollama.
"""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from runner.ollama_runtime import OLLAMA_NOT_INSTALLED, OLLAMA_RUNNING, OllamaRuntime


# =========================================================================
# Real Ollama detection
# =========================================================================


@pytest.fixture(scope="session")
def ollama_runtime() -> OllamaRuntime:
    """The real runtime probe. Discovers the actual `ollama` binary, if any."""
    return OllamaRuntime()


@pytest.fixture(scope="session")
def ollama_state(ollama_runtime) -> str:
    """Authoritative runtime state: RUNNING / STOPPED / UNHEALTHY / NOT_INSTALLED."""
    return ollama_runtime.health().state


@pytest.fixture
def requires_real_ollama(ollama_runtime, ollama_state):
    """
    Skips the test unless a real Ollama installation was found.

    This is an explicit integration-test skip, not a substitute: when the binary
    is absent the test reports SKIPPED with the reason, so the suite never
    implies coverage it does not have.
    """
    if ollama_state == OLLAMA_NOT_INSTALLED:
        pytest.skip(
            "requires the real Ollama runtime: no 'ollama' executable was found on PATH "
            "or in any standard location (set OLLAMA_EXECUTABLE to override). "
            "No stand-in server is substituted."
        )
    return ollama_runtime


@pytest.fixture
def requires_running_ollama(requires_real_ollama, ollama_state):
    """Skips unless real Ollama is installed AND currently healthy."""
    if ollama_state != OLLAMA_RUNNING:
        pytest.skip(f"requires a running Ollama daemon (current state: {ollama_state}).")
    return requires_real_ollama


# =========================================================================
# Generic transport helpers - explicitly NOT Ollama
# =========================================================================


def free_port() -> int:
    """Returns a TCP port the kernel considers free right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def unused_port() -> int:
    """A port with nothing listening, for closed-port assertions."""
    port = free_port()
    # Re-check: nothing bound between release and use.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        assert probe.connect_ex(("127.0.0.1", port)) != 0
    return port


class _CannedHandler(BaseHTTPRequestHandler):
    """Serves one fixed JSON document. Knows nothing about Ollama."""

    payload = {"status": "ok", "served_by": "generic-test-listener"}

    def _respond(self, body: bytes, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - http.server API
        self._respond(json.dumps(self.payload).encode("utf-8"))

    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._respond(json.dumps({**self.payload, "method": "POST"}).encode("utf-8"))

    def log_message(self, *args):  # silence request logging
        pass


@pytest.fixture
def local_http_server():
    """
    Starts a plain HTTP listener on an EPHEMERAL port and yields (host, port, url).

    Used only by tests of generic transport utilities (`check_port`,
    `retry_request`). It deliberately does not bind 11434 and is not an Ollama
    stand-in: tests that need the real runtime use `requires_real_ollama`.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CannedHandler)
    host, port = server.server_address[0], server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield host, port, f"http://{host}:{port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def dead_child_command():
    """
    A fixed argv that exits non-zero immediately, for start-failure tests.

    Used to prove `OllamaRuntime.start()` reports failure when the spawned
    process dies before the port opens (defect D1). It is passed in by the test
    as an explicit executable override - never auto-discovered.
    """
    import sys

    return [sys.executable, "-c", "import sys; sys.stderr.write('fatal: cannot bind\\n'); sys.exit(3)"]
