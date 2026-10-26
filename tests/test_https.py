"""Integração HTTPS local: certificado, SNI, respostas e prazo da sonda."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from fortigate_audit.https import BODY_LIMIT, probe_https
from fortigate_audit.models import Target


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append((self.path, self.headers.get("Host")))
        time.sleep(self.server.delay_headers)
        try:
            self.send_response(self.server.response_status)
            self.send_header("Content-Length", str(len(self.server.body)))
            if self.server.location:
                self.send_header("Location", self.server.location)
            self.end_headers()
            time.sleep(self.server.delay_body)
            self.wfile.write(self.server.body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def log_message(self, *args):
        pass


class HTTPSProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.temp.name) / "server.crt"
        cls.key = Path(cls.temp.name) / "server.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=fortigate.test", "-addext", "subjectAltName=DNS:fortigate.test",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", str(cls.key), "-out", str(cls.cert),
        ], check=True, capture_output=True)
        cls.context = ssl.create_default_context(cafile=str(cls.cert))
        cls.target = Target("Firewall teste", "127.0.0.1", "fortigate.test", "teste:2")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextmanager
    def server(self, *, body=b"<title>FortiGate</title>", status=200, location=None,
               delay_headers=0, delay_body=0):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.body = body
        server.response_status = status
        server.location = location
        server.delay_headers = delay_headers
        server.delay_body = delay_body
        server.requests = []
        server.sni_names = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        context.set_servername_callback(lambda sock, name, ctx: server.sni_names.append(name))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_trusted_https_connects_to_ip_preserving_sni_and_host(self):
        original_getaddrinfo = socket.getaddrinfo
        def only_ip(host, *args, **kwargs):
            self.assertEqual(host, "127.0.0.1", "não deve resolver novamente o nome TLS")
            return original_getaddrinfo(host, *args, **kwargs)

        with self.server() as server, patch("socket.getaddrinfo", side_effect=only_ip):
            port = server.server_port
            result = probe_https(self.target, "127.0.0.1", port, 2, self.context)
            self.assertEqual(result.status, "FORTIGATE_WEB")
            self.assertEqual(result.http_status, 200)
            self.assertEqual(result.ip, "127.0.0.1")
            self.assertEqual(server.sni_names, ["fortigate.test"])
            self.assertEqual(server.requests, [("/", f"fortigate.test:{port}")])

    def test_generic_fortinet_text_is_not_fortigate_identity(self):
        with self.server(body=b"<title>Portal</title>Fortinet") as server:
            result = probe_https(self.target, "127.0.0.1", server.server_port, 2, self.context)
        self.assertEqual(result.status, "WEB")

    def test_login_markers_and_vendor_are_probable_fortigate(self):
        with self.server(body=b"Fortinet <fgt-login></fgt-login>") as server:
            result = probe_https(self.target, "127.0.0.1", server.server_port, 2, self.context)
        self.assertEqual(result.status, "FORTIGATE_WEB")

    def test_401_and_403_are_web_accessible(self):
        for status in (401, 403):
            with self.subTest(status=status), self.server(status=status, body=b"Access denied") as server:
                result = probe_https(self.target, "127.0.0.1", server.server_port, 2, self.context)
            self.assertEqual(result.status, "WEB")
            self.assertEqual(result.http_status, status)

    def test_redirect_is_not_followed_and_hides_credentials_and_query(self):
        with self.server(status=302, location="https://user:secret@outside.test/login?token=secret") as server:
            result = probe_https(self.target, "127.0.0.1", server.server_port, 2, self.context)
            self.assertEqual(len(server.requests), 1)
        self.assertEqual(result.status, "WEB")
        self.assertIn("outside.test", result.detail)
        self.assertNotIn("secret", result.detail)
        self.assertNotIn("user", result.detail)

    def test_untrusted_certificate_does_not_send_http_request(self):
        with self.server() as server:
            result = probe_https(self.target, "127.0.0.1", server.server_port, 2, ssl.create_default_context())
            self.assertEqual(server.requests, [])
        self.assertEqual(result.status, "TLS_UNTRUSTED")
        self.assertIsNone(result.http_status)

    def test_wrong_hostname_does_not_disable_name_validation(self):
        target = Target("Outro", "127.0.0.1", "different.test", "teste:2")
        with self.server() as server:
            result = probe_https(target, "127.0.0.1", server.server_port, 2, self.context)
        self.assertEqual(result.status, "TLS_UNTRUSTED")
        self.assertIn("nome", result.detail)

    def test_connection_refused(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
            # A porta fica reservada, mas não está em listen.
            result = probe_https(self.target, "127.0.0.1", port, 1, self.context)
        self.assertEqual(result.status, "CLOSED")

    def test_header_timeout_does_not_prove_policy_block(self):
        with self.server(delay_headers=0.3) as server:
            start = time.monotonic()
            result = probe_https(self.target, "127.0.0.1", server.server_port, 0.08, self.context)
            elapsed = time.monotonic() - start
        self.assertEqual(result.status, "TIMEOUT")
        self.assertLess(elapsed, 0.8)

    def test_body_timeout_preserves_proven_http_response(self):
        with self.server(delay_body=0.3) as server:
            result = probe_https(self.target, "127.0.0.1", server.server_port, 0.08, self.context)
        self.assertEqual(result.status, "WEB")
        self.assertEqual(result.http_status, 200)
        self.assertIn("incompleta", result.detail)

    def test_body_is_bounded(self):
        with self.server(body=b"x" * (BODY_LIMIT + 5000) + b"<title>FortiGate</title>") as server:
            result = probe_https(self.target, "127.0.0.1", server.server_port, 2, self.context)
        self.assertEqual(result.status, "WEB")


if __name__ == "__main__":
    unittest.main()
