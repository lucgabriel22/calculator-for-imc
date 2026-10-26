"""Saída de terminal com tabelas e progresso, usando somente Python nativo."""

from collections import Counter
from datetime import datetime
import os
from pathlib import Path
import shutil
import sys
import time
from typing import TextIO
import unicodedata

from .models import Result, Target


WEB_STATUSES = {"FORTIGATE_WEB", "WEB"}
LABELS = {
    "FORTIGATE_WEB": ("FortiGate provável", "bold red"),
    "WEB": ("Produto não confirmado", "red"),
    "TLS_UNTRUSTED": ("Certificado não validado", "yellow"),
    "CLOSED": ("Conexão recusada", "cyan"),
    "TIMEOUT": ("Sem resposta no prazo", "yellow"),
    "DNS_ERROR": ("Falha de DNS", "yellow"),
    "ERROR": ("Verificação inconclusiva", "yellow"),
}
_STYLES = {"bold": "1", "dim": "2", "red": "31", "yellow": "33", "cyan": "36"}


def _width(text: str) -> int:
    return sum(0 if unicodedata.combining(char) else
               2 if unicodedata.east_asian_width(char) in "WF" else 1 for char in text)


def _wrap(text: str, width: int) -> list[str]:
    """Quebre texto sem abreviar hostnames, endereços ou detalhes."""
    lines = []
    for original in str(text).split("\n"):
        line = original
        while _width(line) > width:
            cells = 0
            end = 0
            for index, char in enumerate(line):
                cells += _width(char)
                if cells > width:
                    break
                end = index + 1
            end = max(1, end)
            space = line.rfind(" ", 0, end + 1)
            if space > 0:
                end = space
            lines.append(line[:end].rstrip())
            line = line[end:].lstrip()
        lines.append(line)
    return lines


def _windows_ansi(stream: TextIO) -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        import msvcrt
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = ctypes.c_ulong()
        kernel = ctypes.windll.kernel32
        return bool(kernel.GetConsoleMode(handle, ctypes.byref(mode)) and
                    kernel.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError, ValueError):
        return False


class Console:
    """Cores automáticas em TTY; saída simples quando redirecionada."""

    def __init__(self, stream: TextIO | None = None, stderr: bool = False,
                 width: int | None = None):
        self.stream = stream if stream is not None else (sys.stderr if stderr else sys.stdout)
        self.width = max(20, width if width is not None else shutil.get_terminal_size((100, 24)).columns)
        self.is_terminal = bool(getattr(self.stream, "isatty", lambda: False)())
        self.color = (self.is_terminal and "NO_COLOR" not in os.environ and
                      os.environ.get("TERM") != "dumb" and _windows_ansi(self.stream))

    def print(self, text: str = "", style: str | None = None) -> None:
        value = str(text).replace("\x1b", "?")
        codes = [_STYLES[part] for part in (style or "").split() if part in _STYLES]
        if self.color and codes:
            value = f"\x1b[{';'.join(codes)}m{value}\x1b[0m"
        self.stream.write(value + "\n")
        self.stream.flush()

    def paragraph(self, text: str, style: str | None = None) -> None:
        for line in _wrap(text, self.width):
            self.print(line, style)

    def heading(self, text: str, style: str = "cyan") -> None:
        self.print()
        self.paragraph(text, "bold " + style)
        self.print("-" * min(self.width, max(12, _width(text))), style)

    def table(self, headers: list[str], rows: list[list[str]], weights: list[int] | None = None,
              style: str = "cyan") -> None:
        """Tabelas em telas largas e cartões sem perdas em telas estreitas."""
        minimums = [max(5, min(_width(header), 12)) for header in headers]
        available = self.width - (3 * len(headers) + 1)
        if available < sum(minimums):
            for number, row in enumerate(rows, 1):
                self.print(f"[{number}]", style)
                for header, value in zip(headers, row):
                    self.paragraph(f"{header}: {value}")
                self.print()
            return
        widths = minimums[:]
        weights = weights or [1] * len(headers)
        flexible = [index for index, header in enumerate(headers) if header not in {"Porta", "HTTP"}]
        for _ in range(available - sum(widths)):
            index = min(flexible or range(len(widths)), key=lambda item: widths[item] / weights[item])
            widths[index] += 1
        border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
        self.print(border, style)
        for row_number, row in enumerate([headers] + rows):
            cells = [_wrap(str(value), width) for value, width in zip(row, widths)]
            for line_number in range(max(map(len, cells))):
                parts = []
                for cell, width in zip(cells, widths):
                    value = cell[line_number] if line_number < len(cell) else ""
                    parts.append(value + " " * (width - _width(value)))
                self.print("| " + " | ".join(parts) + " |", "bold" if row_number == 0 else None)
            self.print(border, style)


class Progress:
    """Uma linha atualizada em TTY; silenciosa em arquivos e pipes."""

    def __init__(self, console: Console):
        self.console = console
        self.description = ""
        self.completed = 0
        self.total = 0
        self.started = time.monotonic()
        self._last_width = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.console.is_terminal and self._last_width:
            self.console.stream.write("\r" + " " * self._last_width + "\r")
            self.console.stream.flush()

    def update(self, description: str, completed: int = 0, total: int = 0) -> None:
        self.description, self.completed, self.total = description, completed, total
        self._draw()

    def advance(self, step: int = 1) -> None:
        self.completed += step
        self._draw()

    def _draw(self) -> None:
        if not self.console.is_terminal:
            return
        elapsed = time.monotonic() - self.started
        count = f"{self.completed}/{self.total}"
        remaining = max(1, self.console.width - len(count) - 15)
        description = _wrap(self.description, remaining)[0]
        text = f"{description}  {count}  {elapsed:.1f}s"
        padding = max(0, self._last_width - _width(text))
        self.console.stream.write("\r" + text + " " * padding)
        self.console.stream.flush()
        self._last_width = _width(text)


def show_header(console: Console, workbook: Path, origin: str,
                ports: tuple[int, ...], count: int) -> None:
    console.heading("FORTIGATE | Verificação externa de interfaces HTTPS")
    for label, value in (
        ("Planilha", str(workbook.resolve())), ("Origem", origin),
        ("Alvos", str(count)), ("Portas", ", ".join(map(str, ports))),
    ):
        console.paragraph(f"{label}: {value}")
    console.print()


def show_targets(console: Console, targets: list[Target]) -> None:
    console.heading("ALVOS DA PLANILHA")
    console.table(["Host", "Destino", "Nome TLS", "Aba / linha"], [
        [target.host, target.address, target.tls_name, target.source] for target in targets
    ])
    console.paragraph("Somente leitura da planilha. Nenhuma conexão realizada.", "dim")


def show_results(console: Console, results: list[Result], started: datetime) -> None:
    web = [result for result in results if result.status in WEB_STATUSES]
    untrusted = [result for result in results if result.status == "TLS_UNTRUSTED"]
    remaining = [result for result in results if result.status not in WEB_STATUSES | {"TLS_UNTRUSTED"}]
    counts = Counter(result.status for result in results)
    finished = datetime.now().astimezone()
    elapsed = max(0, (finished - started).total_seconds())
    console.heading("RESULTADO FINAL")
    for label, count, style in (
        ("Verificações", len(results), "bold"),
        ("Web acessível", len(web), "bold red" if web else "bold"),
        ("FortiGate provável", counts["FORTIGATE_WEB"], "red" if counts["FORTIGATE_WEB"] else "dim"),
        ("TLS sem validação", len(untrusted), "yellow" if untrusted else "dim"),
        ("Outros resultados", len(remaining), "cyan"),
    ):
        console.paragraph(f"  {label:<20} {count}", style)
    console.paragraph(f"Concluído em {elapsed:.1f}s | {finished.isoformat(timespec='seconds')}", "dim")
    for title, group, style in (
        ("INTERFACES WEB ACESSÍVEIS", web, "red"),
        ("TLS RESPONDEU — WEB INCONCLUSIVA", untrusted, "yellow"),
        ("DEMAIS RESULTADOS", remaining, "cyan"),
    ):
        if group:
            console.heading(title, style)
            console.table(["Host", "IP", "Porta", "HTTP", "Resultado / detalhe"], [
                [result.host, result.ip, str(result.port),
                 str(result.http_status) if result.http_status is not None else "—",
                 LABELS[result.status][0] + "\n" + result.detail] for result in group
            ], weights=[2, 2, 1, 1, 4], style=style)
    console.print()
    console.paragraph(
        "Resultado válido para esta origem e horário. "
        "A regra local-in policy não é verificável externamente; confirme-a na configuração do FortiGate.",
        "dim",
    )
    console.paragraph("IPs privados/reservados demonstram apenas alcance a partir da rede de execução.", "dim")
