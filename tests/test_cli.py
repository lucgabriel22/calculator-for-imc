"""Fluxo XLSX -> HTTPS real local -> terminal, sem acessar equipamentos reais."""

from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from openpyxl import Workbook

from verificar_fortigate import main


ROOT = Path(__file__).resolve().parents[1]


class _FortigatePage(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><title>FortiGate</title><body>Fixture local</body></html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_directory = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.cert_directory.name) / "ca.pem"
        key = Path(cls.cert_directory.name) / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=fw.test", "-addext", "subjectAltName=DNS:fw.test",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", str(key), "-out", str(cls.cert),
        ], check=True, capture_output=True)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FortigatePage)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.cert_directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "caixas.xlsx"
        self.output = Path(self.directory.name) / "resultado.txt"

    def tearDown(self):
        self.directory.cleanup()

    def workbook(self, host="fw.test", ip="127.0.0.1"):
        workbook = Workbook()
        sheet = workbook.active
        sheet.append(["Host", "IP"])
        sheet.append([host, ip])
        workbook.save(self.path)
        workbook.close()

    def run_cli(self, *args):
        environment = os.environ.copy()
        environment["COLUMNS"] = "140"
        return subprocess.run(
            [sys.executable, str(ROOT / "verificar_fortigate.py"), str(self.path), *args],
            text=True, capture_output=True, timeout=15, cwd=self.directory.name,
            env=environment,
        )

    def assert_no_generated_files(self, previous_files):
        self.assertEqual(set(Path(self.directory.name).rglob("*")), previous_files)

    def test_real_xlsx_https_and_terminal_with_exposed_and_refused_ports(self):
        self.workbook()
        previous_files = set(Path(self.directory.name).rglob("*"))
        with socket.socket() as refused:
            refused.bind(("127.0.0.1", 0))
            refused_port = refused.getsockname()[1]
            completed = self.run_cli(
                "--ca", str(self.cert),
                "--portas", f"{self.server.server_port},{refused_port}",
                "--origem", "Fixture HTTPS local, dados sintéticos",
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = completed.stdout
        self.assertIn("fw.test", output)
        self.assertIn("127.0.0.1", output)
        self.assertIn(str(self.server.server_port), output)
        self.assertIn("200", output)
        self.assertIn("FortiGate provável", output)
        self.assertIn(str(refused_port), output)
        self.assertIn("Conexão recusada", output)
        self.assertRegex(output, r"Verificações\s*[:│]?\s*2\b")
        self.assertRegex(output, r"Web acessível\s*[:│]?\s*1\b")
        self.assertIn("local-in policy não é verificável externamente", output)
        self.assertNotIn("\x1b[", output)
        self.assert_no_generated_files(previous_files)

    def test_untrusted_cert_is_not_reported_as_closed_or_confirmed_web(self):
        self.workbook()
        previous_files = set(Path(self.directory.name).rglob("*"))
        completed = self.run_cli("--portas", str(self.server.server_port))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = completed.stdout
        self.assertRegex(output, r"Web acessível\s*[:│]?\s*0\b")
        self.assertRegex(output, r"TLS sem validação\s*[:│]?\s*1\b")
        self.assertIn("TLS RESPONDEU", output)
        self.assertIn("Certificado não validado", output)
        self.assertNotIn("Conexão recusada", output)
        self.assert_no_generated_files(previous_files)

    def test_list_only_never_scans(self):
        self.workbook()
        with patch("verificar_fortigate.scan") as scan, redirect_stdout(StringIO()) as output:
            code = main([str(self.path), "--listar"])
        self.assertEqual(code, 0)
        scan.assert_not_called()
        self.assertIn("fw.test", output.getvalue())
        self.assertFalse(self.output.exists())

    def test_dns_failure_is_reported_for_each_requested_port(self):
        self.workbook(host="does-not-resolve.invalid", ip=None)
        with patch("verificar_fortigate.socket.getaddrinfo", side_effect=socket.gaierror), \
             patch("verificar_fortigate.probe_https") as probe, \
             patch.dict(os.environ, {"COLUMNS": "140"}), redirect_stdout(StringIO()) as captured:
            code = main([str(self.path)])
        self.assertEqual(code, 0)
        probe.assert_not_called()
        output = captured.getvalue()
        self.assertEqual(output.count("Falha de DNS"), 3)
        for port in (4443, 4434, 4461):
            self.assertIn(str(port), output)
        self.assertFalse(self.output.exists())

    def test_existing_result_file_is_preserved_and_no_new_files_created(self):
        self.workbook()
        self.output.write_text("arquivo do usuário", encoding="utf-8")
        previous_files = set(Path(self.directory.name).rglob("*"))
        completed = self.run_cli("--portas", str(self.server.server_port), "--ca", str(self.cert))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "arquivo do usuário")
        self.assert_no_generated_files(previous_files)

    def test_removed_output_option_is_rejected(self):
        self.workbook()
        completed = self.run_cli("--saida", str(self.output))
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--saida", completed.stderr)
        self.assertFalse(self.output.exists())

    def test_multiple_dns_ips_are_all_tested(self):
        from fortigate_audit.models import Result

        self.workbook(host="fw.test", ip=None)
        def result(target, ip, port, timeout, context):
            return Result(target.host, ip, port, "WEB", "fixture", 403)
        with patch("verificar_fortigate.resolve_ips", return_value=["192.0.2.1", "2001:db8::1"]), \
             patch("verificar_fortigate.probe_https", side_effect=result), \
             patch.dict(os.environ, {"COLUMNS": "140"}), redirect_stdout(StringIO()) as captured:
            code = main([str(self.path)])
        self.assertEqual(code, 0)
        output = captured.getvalue()
        self.assertRegex(output, r"Verificações\s*[:│]?\s*6\b")
        self.assertEqual(output.count("Produto não confirmado"), 6)
        self.assertEqual(output.count("192.0.2.1"), 3)
        self.assertEqual(output.count("2001:db8::1"), 3)
        self.assertFalse(self.output.exists())

    def test_corrupt_xlsx_returns_readable_error_without_traceback(self):
        self.path.write_text("não é um arquivo XLSX", encoding="utf-8")
        completed = self.run_cli("--listar")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("Erro:", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
