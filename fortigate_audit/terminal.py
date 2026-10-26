"""Apresentação dos alvos e resultados diretamente no terminal."""

from collections import Counter
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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


def show_header(console: Console, workbook: Path, origin: str,
                ports: tuple[int, ...], count: int) -> None:
    console.print(Panel(
        Text.assemble(("FORTIGATE", "bold cyan"), "\nVerificação externa de interfaces HTTPS"),
        border_style="cyan", padding=(1, 2),
    ))
    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim", no_wrap=True)
    info.add_column(overflow="fold")
    for label, value in (
        ("Planilha", str(workbook.resolve())),
        ("Origem", origin),
        ("Alvos", str(count)),
        ("Portas", ", ".join(map(str, ports))),
    ):
        info.add_row(label, Text(value))
    console.print(info)
    console.print()


def show_targets(console: Console, targets: list[Target]) -> None:
    table = Table(title="ALVOS DA PLANILHA", box=box.ROUNDED,
                  border_style="cyan", header_style="bold cyan", expand=True)
    for name in ("Host", "Destino", "Nome TLS", "Aba / linha"):
        table.add_column(name, overflow="fold")
    for target in targets:
        table.add_row(*(Text(value) for value in (
            target.host, target.address, target.tls_name, target.source,
        )))
    console.print(table)
    console.print("Somente leitura da planilha. Nenhuma conexão realizada.", style="dim")


def _result_table(title: str, results: list[Result], style: str) -> Table:
    table = Table(title=title, box=box.ROUNDED, border_style=style,
                  header_style=f"bold {style}", expand=True, show_lines=True)
    table.add_column("Host", ratio=2, overflow="fold")
    table.add_column("IP", ratio=2, overflow="fold")
    table.add_column("Porta", justify="right", no_wrap=True)
    table.add_column("HTTP", justify="right", no_wrap=True)
    table.add_column("Resultado / detalhe", ratio=4, overflow="fold")
    for result in results:
        label, color = LABELS[result.status]
        description = Text(label, style=color)
        description.append("\n" + result.detail, style="dim")
        table.add_row(Text(result.host), Text(result.ip), str(result.port),
                      str(result.http_status) if result.http_status is not None else "—",
                      description)
    return table


def show_results(console: Console, results: list[Result], started: datetime) -> None:
    web = [result for result in results if result.status in WEB_STATUSES]
    untrusted = [result for result in results if result.status == "TLS_UNTRUSTED"]
    remaining = [result for result in results if result.status not in WEB_STATUSES | {"TLS_UNTRUSTED"}]
    counts = Counter(result.status for result in results)
    finished = datetime.now().astimezone()
    elapsed = max(0, (finished - started).total_seconds())
    console.rule("RESULTADO FINAL", style="cyan")
    summary = Table.grid(padding=(0, 2))
    summary.add_column()
    summary.add_column(justify="right")
    for label, count, style in (
        ("Verificações", len(results), "bold"),
        ("Web acessível", len(web), "bold red" if web else "bold"),
        ("FortiGate provável", counts["FORTIGATE_WEB"], "red" if counts["FORTIGATE_WEB"] else "dim"),
        ("TLS sem validação", len(untrusted), "yellow" if untrusted else "dim"),
        ("Outros resultados", len(remaining), "cyan"),
    ):
        summary.add_row(Text(label, style=style), Text(str(count), style=style))
    console.print(Panel(summary, title="Resumo", border_style="cyan", padding=(1, 2)))
    console.print(Text(f"Concluído em {elapsed:.1f}s • {finished.isoformat(timespec='seconds')}", style="dim"))
    console.print()
    for title, group, style in (
        ("INTERFACES WEB ACESSÍVEIS", web, "red"),
        ("TLS RESPONDEU — WEB INCONCLUSIVA", untrusted, "yellow"),
        ("DEMAIS RESULTADOS", remaining, "cyan"),
    ):
        if group:
            console.print(_result_table(title, group, style))
            console.print()
    console.print(Text(
        "Resultado válido para esta origem e horário. "
        "A regra local-in policy não é verificável externamente; confirme-a na configuração do FortiGate.\n"
        "IPs privados/reservados demonstram apenas alcance a partir da rede de execução.",
        style="dim",
    ))
