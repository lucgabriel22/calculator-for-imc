"""Sonda HTTPS sem autenticação, com destino IP e validação TLS explícitos."""

import errno
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from .models import Result, Target


BODY_LIMIT = 128 * 1024


class _DirectHTTPSConnection(http.client.HTTPSConnection):
    """Conecta ao IP informado preservando o nome de Host e de SNI."""

    def __init__(self, name: str, ip: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(name, port, timeout=timeout, context=context)
        self.ip = ip
        self.deadline = time.monotonic() + timeout
        self.expired = threading.Event()
        self.transport: ssl.SSLSocket | socket.socket | None = None

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.expired.is_set():
            raise TimeoutError("prazo da verificação excedido")
        return remaining

    def abort(self) -> None:
        self.expired.set()
        sock = self.sock or self.transport
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def connect(self) -> None:
        self.sock = socket.create_connection((self.ip, self.port), self.remaining())
        self.transport = self.sock
        try:
            self.sock.settimeout(self.remaining())
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
            self.transport = self.sock
            self.sock.settimeout(self.remaining())
        except BaseException:
            self.close()
            raise


def _redirect_description(location: str | None) -> str:
    """Não copia caminhos, parâmetros ou credenciais de redirects para o relatório."""
    if not location:
        return "redirecionamento recebido, sem destino; não seguido"
    try:
        parsed = urlsplit(location)
        hostname = parsed.hostname
        if hostname and re.fullmatch(r"[A-Za-z0-9.:-]+", hostname):
            host = f"[{hostname}]" if ":" in hostname else hostname
            port = f":{parsed.port}" if parsed.port else ""
            scheme = parsed.scheme.lower()
            if scheme in ("https", "http"):
                return f"redirecionamento para {scheme}://{host}{port}/…; não seguido"
        return "redirecionamento recebido; não seguido"
    except ValueError:
        return "redirecionamento com destino inválido; não seguido"


def _has_fortigate_indicators(body: bytes) -> bool:
    html = body.decode("utf-8", errors="replace")
    title = re.search(r"<title\b[^>]*>(.*?)</title\s*>", html, re.I | re.S)
    if title and re.search(r"\b(?:FortiGate|FortiOS)\b", title.group(1), re.I):
        return True
    lowered = html.lower()
    return "fortinet" in lowered and any(marker in lowered for marker in ("<fgt-login", "fgt_lang"))


def _certificate_description(error: ssl.SSLCertVerificationError) -> str:
    descriptions = {
        10: "certificado expirado",
        18: "certificado autoassinado",
        19: "cadeia com certificado autoassinado",
        20: "autoridade certificadora não confiável ou cadeia incompleta",
        21: "cadeia do certificado não verificável",
        62: "nome do certificado diferente do host",
        64: "IP diferente do certificado",
    }
    reason = descriptions.get(getattr(error, "verify_code", None), "certificado não validado")
    return f"TLS respondeu, mas {reason}; resposta web não confirmada. Use uma CA confiável quando aplicável"


def probe_https(target: Target, ip: str, port: int, timeout: float, context: ssl.SSLContext) -> Result:
    """Faz somente GET /; nunca segue redirects nem ignora erros de certificado.

    WEB significa que uma resposta HTTP foi recebida desta origem. Não determina
    a regra local-in policy, nem comprova que o equipamento seja um FortiGate.
    """
    def result(status: str, detail: str, http_status: int | None = None) -> Result:
        return Result(target.host, ip, port, status, detail, http_status)

    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        return result("ERROR", "o contexto TLS precisa validar a cadeia e o nome do certificado")
    try:
        ipaddress.ip_address(ip)
        if not 1 <= port <= 65535 or timeout <= 0:
            raise ValueError
    except ValueError:
        return result("ERROR", "IP, porta ou timeout inválido")

    connection = _DirectHTTPSConnection(target.tls_name, ip, port, timeout, context)
    timer = threading.Timer(timeout, connection.abort)
    timer.daemon = True
    timer.start()
    response = None
    try:
        connection.request("GET", "/", headers={
            "User-Agent": "FortiGate-Exposure-Check/1.0",
            "Accept": "text/html, */*;q=0.1",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        response = connection.getresponse()
        status = response.status
        if 300 <= status < 400:
            return result("WEB", f"HTTP {status}; {_redirect_description(response.getheader('Location'))}", status)

        body = bytearray()
        incomplete = False
        try:
            while len(body) < BODY_LIMIT:
                remaining = connection.remaining()
                if connection.transport is not None:
                    connection.transport.settimeout(remaining)
                chunk = response.read1(min(8192, BODY_LIMIT - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
        except (OSError, http.client.HTTPException):
            # Os cabeçalhos já comprovam uma resposta web, mesmo sem corpo completo.
            incomplete = True

        detail = f"HTTP {status}; interface web acessível desta origem"
        if incomplete or connection.expired.is_set():
            detail += "; leitura do conteúdo incompleta"
        if _has_fortigate_indicators(bytes(body)):
            return result("FORTIGATE_WEB", detail + "; indícios de FortiGate/FortiOS no conteúdo", status)
        return result("WEB", detail + "; equipamento não identificado", status)
    except ssl.SSLCertVerificationError as error:
        return result("TLS_UNTRUSTED", _certificate_description(error))
    except (TimeoutError, socket.timeout):
        return result("TIMEOUT", "sem resposta HTTPS no prazo; bloqueio de política não comprovado")
    except ConnectionRefusedError:
        return result("CLOSED", "conexão recusada; nenhuma resposta web recebida")
    except ssl.SSLError:
        if connection.expired.is_set():
            return result("TIMEOUT", "prazo excedido durante a negociação TLS")
        return result("ERROR", "falha na negociação TLS; resposta web não confirmada")
    except http.client.HTTPException:
        if connection.expired.is_set():
            return result("TIMEOUT", "sem resposta HTTP completa no prazo")
        return result("ERROR", "resposta incompatível com HTTP; resposta web não confirmada")
    except OSError as error:
        if connection.expired.is_set():
            return result("TIMEOUT", "sem resposta HTTPS no prazo; bloqueio de política não comprovado")
        if error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            return result("ERROR", "destino sem rota de rede desta origem")
        return result("ERROR", "falha de conexão; resposta web não confirmada")
    finally:
        timer.cancel()
        if response is not None:
            response.close()
        connection.close()
