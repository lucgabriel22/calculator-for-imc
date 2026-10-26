#!/usr/bin/env python3
"""Leia um XLSX e verifique a exposição HTTPS dos equipamentos listados."""

from __future__ import annotations

import argparse
import ipaddress
import math
import socket
import ssl
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from fortigate_audit.https import probe_https
from fortigate_audit.models import Result, Target
from fortigate_audit.planilha import load_targets
from fortigate_audit.terminal import Console, Progress, show_header, show_results, show_targets


def parse_ports(value: str) -> tuple[int, ...]:
    try:
        ports = tuple(dict.fromkeys(int(item.strip()) for item in value.split(",")))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Informe portas separadas por vírgula.") from exc
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise argparse.ArgumentTypeError("As portas devem estar entre 1 e 65535.")
    return ports


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("O timeout deve ser um número positivo.") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= 120:
        raise argparse.ArgumentTypeError("Use um timeout maior que zero e até 120 segundos.")
    return timeout


def worker_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("A quantidade de tarefas deve ser um inteiro.") from exc
    if not 1 <= count <= 64:
        raise argparse.ArgumentTypeError("Use entre 1 e 64 tarefas simultâneas.")
    return count


def arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verifica HTTPS nos hosts de um XLSX e exibe os resultados no terminal. "
            "Execute na conexão externa que deseja testar. A política local-in "
            "não pode ser determinada apenas por esta verificação."
        )
    )
    parser.add_argument("planilha", type=Path, help="Arquivo .xlsx com os hosts e/ou IPs.")
    parser.add_argument("--aba", help="Nome exato de uma aba; por padrão, examina todas as abas.")
    parser.add_argument("--coluna-host", help="Nome do cabeçalho da coluna de host/equipamento.")
    parser.add_argument("--coluna-ip", help="Nome do cabeçalho da coluna de IP ou DNS de destino.")
    parser.add_argument("--portas", type=parse_ports, default=(4443, 4434, 4461), help="Padrão: 4443,4434,4461.")
    parser.add_argument("--timeout", type=positive_timeout, default=5.0, help="Limite por consulta HTTPS, sem incluir DNS (segundos; padrão: 5).")
    parser.add_argument("--tarefas", type=worker_count, default=8, help="Verificações simultâneas (padrão: 8, máximo: 64).")
    parser.add_argument("--ca", type=Path, help="CA adicional em PEM para validar certificados privados.")
    parser.add_argument("--origem", default="Não informada", help="Descrição da conexão de teste exibida no terminal.")
    parser.add_argument("--listar", action="store_true", help="Mostra os alvos lidos, sem resolver DNS ou acessar a rede.")
    parser.add_argument("--ignorar-invalidos", action="store_true", help="Processa apenas as linhas válidas e avisa cada linha ignorada; por padrão, erros interrompem a leitura.")
    return parser.parse_args(argv)


def resolve_ips(address: str) -> list[str]:
    """Resolva todos os IPs do destino; uma linha pode produzir vários resultados."""
    try:
        return [str(ipaddress.ip_address(address))]
    except ValueError:
        answers = socket.getaddrinfo(address, None, type=socket.SOCK_STREAM)
        ips = list(dict.fromkeys(answer[4][0] for answer in answers))
        if not ips:
            raise socket.gaierror("Nenhum endereço IPv4/IPv6 encontrado.")
        return ips


def scan(targets: list[Target], ports: tuple[int, ...], timeout: float,
         workers: int, context: ssl.SSLContext, console: Console) -> list[Result]:
    results: list[Result] = []
    endpoints: list[tuple[Target, str, int]] = []
    # DNS é feito antes das conexões. Depois, cada socket usa exatamente o IP relatado.
    with Progress(console) as progress, ThreadPoolExecutor(max_workers=workers) as pool:
        progress.update("Resolvendo destinos", total=len(targets))
        resolutions = {pool.submit(resolve_ips, target.address): target for target in targets}
        for future in as_completed(resolutions):
            target = resolutions[future]
            try:
                ips = future.result()
            except OSError:
                for port in ports:
                    results.append(Result(target.host, "não resolvido", port, "DNS_ERROR",
                                          f"Não foi possível resolver {target.address}."))
                progress.advance()
                continue
            endpoints.extend((target, ip, port) for ip in ips for port in ports)
            progress.advance()

        progress.update("Consultando HTTPS", completed=0, total=len(endpoints))
        futures = {
            pool.submit(probe_https, target, ip, port, timeout, context): (target, ip, port)
            for target, ip, port in endpoints
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            progress.advance()
    return sorted(results, key=lambda item: (item.host.casefold(), item.ip, item.port))


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv)
    started = datetime.now().astimezone()
    console = Console()
    try:
        if any(ord(char) < 32 or ord(char) == 127 for char in args.origem):
            raise ValueError("A descrição da origem não pode conter caracteres de controle.")
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            targets = load_targets(args.planilha, args.aba, args.coluna_host, args.coluna_ip,
                                   skip_invalid=args.ignorar_invalidos)
        notices = [str(warning.message) for warning in recorded]
        show_header(console, args.planilha, args.origem, args.portas, len(targets))
        for notice in notices:
            console.print(f"AVISO: {notice}", style="yellow")
        if args.ignorar_invalidos and notices:
            console.print(f"Atenção: {len(notices)} aviso(s) de leitura; confira as linhas e abas ignoradas.", style="yellow")
        if args.listar:
            show_targets(console, targets)
            return 0

        context = ssl.create_default_context()
        if args.ca:
            context.load_verify_locations(cafile=str(args.ca))
        console.print("Verificação HTTPS iniciada. A origem é a conexão desta máquina.", style="dim")
        results = scan(targets, args.portas, args.timeout, args.tarefas, context, console)
        show_results(console, results, started)
        return 0
    except (ValueError, OSError, ssl.SSLError) as exc:
        Console(stderr=True).print(f"Erro: {exc}", style="bold red")
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        Console(stderr=True).print("\nVerificação interrompida antes do resumo final.", style="yellow")
        sys.exit(130)
