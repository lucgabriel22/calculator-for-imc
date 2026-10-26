"""Estruturas compartilhadas pela leitura, verificação e relatório."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    host: str
    address: str
    tls_name: str
    source: str


@dataclass(frozen=True)
class Result:
    host: str
    ip: str
    port: int
    status: str
    detail: str
    http_status: int | None = None
