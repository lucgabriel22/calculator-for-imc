"""Validação da apresentação nativa, sem bibliotecas instaladas."""

from datetime import datetime
from io import StringIO
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from fortigate_audit.models import Result, Target
from fortigate_audit.terminal import Console, Progress, _width, _wrap, show_header, show_results, show_targets


class _TTY(StringIO):
    def isatty(self):
        return True


class TerminalTests(unittest.TestCase):
    def test_redirected_output_has_no_ansi_or_markup_interpretation(self):
        output = StringIO()
        console = Console(output, width=100)
        console.print("[red]Filial[/red]", "bold red")
        self.assertEqual(output.getvalue(), "[red]Filial[/red]\n")
        self.assertNotIn("\x1b", output.getvalue())

    def test_tty_color_respects_no_color_and_term_dumb(self):
        for settings in ({"NO_COLOR": ""}, {"TERM": "dumb"}):
            with self.subTest(settings=settings), patch.dict(os.environ, settings, clear=True):
                output = _TTY()
                Console(output).print("Resultado", "bold red")
                self.assertNotIn("\x1b", output.getvalue())
        with patch.dict(os.environ, {"TERM": "xterm"}, clear=True), \
             patch("fortigate_audit.terminal._windows_ansi", return_value=True):
            output = _TTY()
            Console(output).print("Resultado", "bold red")
            self.assertEqual(output.getvalue(), "\x1b[1;31mResultado\x1b[0m\n")

    def test_multibyte_wrapping_retains_combining_and_wide_characters(self):
        original = "SãoPaulo-界界-e\u0301-2001:db8:1234:5678:90ab:cdef:1234:5678"
        wrapped = _wrap(original, 12)
        self.assertEqual("".join(wrapped), original)
        self.assertTrue(all(_width(line) <= 12 for line in wrapped))

    def test_table_wraps_long_names_and_ipv6_without_truncation(self):
        output = StringIO()
        console = Console(output, width=80)
        ip = "2001:db8:1234:5678:90ab:cdef:1234:5678"
        host = "firewall-filial-sp.example.com"
        console.table(["Host", "IP", "Porta", "Resultado"], [[host, ip, "4443", "Web acessível"]])
        rendered = output.getvalue()
        rows = [line.split("|") for line in rendered.splitlines() if line.startswith("|")][1:]
        self.assertEqual("".join(row[1].strip() for row in rows), host)
        self.assertEqual("".join(row[2].strip() for row in rows), ip)
        self.assertTrue(all(_width(line) <= 80 for line in rendered.splitlines()))
        self.assertNotIn("...", rendered)

    def test_small_terminal_uses_complete_cards(self):
        output = StringIO()
        ip = "2001:db8:1234:5678:90ab:cdef:1234:5678"
        console = Console(output, width=30)
        show_targets(console, [Target("Firewall São Paulo", ip, ip, "Inventário:linha 23")])
        rendered = output.getvalue()
        self.assertIn("[1]", rendered)
        self.assertIn(ip, "".join(rendered.split()))
        self.assertIn("Firewall São Paulo", rendered)
        self.assertTrue(all(_width(line) <= 30 for line in rendered.splitlines()))

    def test_result_summary_keeps_accessible_and_untrusted_separate(self):
        output = StringIO()
        results = [
            Result("Exposto", "192.0.2.1", 4443, "FORTIGATE_WEB", "HTTP 200", 200),
            Result("Certificado", "192.0.2.2", 4434, "TLS_UNTRUSTED", "TLS sem confiança"),
            Result("Recusado", "192.0.2.3", 4461, "CLOSED", "Conexão recusada"),
        ]
        show_results(Console(output, width=140), results, datetime.now().astimezone())
        rendered = output.getvalue()
        self.assertRegex(rendered, r"Web acessível\s+1")
        self.assertRegex(rendered, r"TLS sem validação\s+1")
        self.assertIn("INTERFACES WEB ACESSÍVEIS", rendered)
        self.assertIn("TLS RESPONDEU", rendered)
        self.assertIn("DEMAIS RESULTADOS", rendered)
        self.assertIn("local-in policy não é verificável externamente", rendered)
        self.assertNotIn("\x1b", rendered)

    def test_header_treats_inventory_text_as_plain_data(self):
        output = StringIO()
        show_header(Console(output, width=100), Path("caixas.xlsx"), "[red]Internet externa[/red]", (4443, 4434, 4461), 5)
        self.assertIn("[red]Internet externa[/red]", output.getvalue())
        self.assertIn("4443, 4434, 4461", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())

    def test_progress_is_silent_when_redirected_and_clears_tty(self):
        output = StringIO()
        with Progress(Console(output)) as progress:
            progress.update("Consultando HTTPS", total=2)
            progress.advance()
        self.assertEqual(output.getvalue(), "")
        tty = _TTY()
        with Progress(Console(tty, width=50)) as progress:
            progress.update("Consultando HTTPS", total=2)
            progress.advance(2)
        self.assertIn("2/2", tty.getvalue())
        self.assertTrue(tty.getvalue().endswith("\r"))
        self.assertNotIn("\x1b", tty.getvalue())


if __name__ == "__main__":
    unittest.main()
