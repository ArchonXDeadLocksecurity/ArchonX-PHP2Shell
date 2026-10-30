"""ArchonX target fingerprinting — Phase 0.

Pure HTTP probes. No exploitation, no writes on the target.

Detects PHP version, OS, SAPI, MPM, session.upload_progress status, and
whether the target's PHP version falls inside the vulnerable range for
CVE-2026-109618 / CVE-2026-109619.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field

from .branding import log


PATCHED_VERSIONS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

BOUNDARY = "----archonx-recon"


@dataclass
class TargetInfo:
    url: str = ""
    reachable: bool = False
    php_version: str = ""
    php_version_tuple: tuple = ()
    os_hint: str = ""
    server: str = ""
    sapi: str = ""
    mpm: str = ""
    upload_progress: str = ""
    vulnerable: bool = False
    vulns: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)


def _conn(host: str, port: int, use_tls: bool, timeout: float = 10):
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(
            host, port, timeout=timeout, context=ctx
        )
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _get(host: str, port: int, path: str, tls: bool, timeout: float = 10,
         extra_headers: dict | None = None) -> tuple[int, dict, bytes]:
    conn = _conn(host, port, tls, timeout)
    hdrs = {"Host": host, "Connection": "close",
            "User-Agent": "Mozilla/5.0 (archonx)"}
    if extra_headers:
        hdrs.update(extra_headers)
    try:
        conn.request("GET", path, headers=hdrs)
        r = conn.getresponse()
        body = r.read(1 << 20)
        headers = {k.lower(): v for k, v in r.getheaders()}
        return r.status, headers, body
    except (OSError, http.client.HTTPException):
        return 0, {}, b""
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _post_multipart(host: str, port: int, path: str, tls: bool,
                    fields: list[tuple[str, str, bytes | None]],
                    timeout: float = 10) -> tuple[int, dict, bytes]:
    parts = []
    for name, value, filename_data in fields:
        if filename_data is not None:
            parts.append(
                (f"--{BOUNDARY}\r\nContent-Disposition: form-data; "
                 f'name="{name}"; filename="probe.txt"\r\n'
                 f"Content-Type: application/octet-stream\r\n\r\n").encode()
                + filename_data + b"\r\n"
            )
        else:
            parts.append(
                (f"--{BOUNDARY}\r\nContent-Disposition: form-data; "
                 f'name="{name}"\r\n\r\n{value}\r\n').encode()
            )
    body = b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()

    conn = _conn(host, port, tls, timeout)
    try:
        conn.request("POST", path, body=body, headers={
            "Host": host,
            "Connection": "close",
            "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
            "Content-Length": str(len(body)),
            "User-Agent": "Mozilla/5.0 (archonx)",
        })
        r = conn.getresponse()
        resp_body = r.read(1 << 20)
        headers = {k.lower(): v for k, v in r.getheaders()}
        return r.status, headers, resp_body
    except (OSError, http.client.HTTPException):
        return 0, {}, b""
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _parse_php_version(s: str) -> tuple:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s)
    if m:
        return tuple(int(x) for x in m.groups())
    return ()


def _detect_os(server: str, headers: dict, body: bytes) -> str:
    combined = (server + " " + str(headers) + " " +
                body.decode("latin1", "replace")).lower()
    if "debian" in combined:
        return "Debian"
    if "ubuntu" in combined:
        return "Ubuntu"
    if "centos" in combined or "el7" in combined or "el8" in combined:
        return "CentOS/RHEL"
    if "red hat" in combined or "rhel" in combined:
        return "RHEL"
    if "alpine" in combined:
        return "Alpine"
    if "win" in server.lower() or "iis" in server.lower():
        return "Windows"
    if "unix" in combined or "linux" in combined:
        return "Linux"
    return ""


def _detect_sapi(server: str, headers: dict) -> str:
    s = server.lower()
    if "php/" in s:
        return "mod_php"
    via = headers.get("via", "").lower()
    if "fastcgi" in via or "fpm" in via:
        return "php-fpm"
    xpb = headers.get("x-powered-by", "").lower()
    if "php-fpm" in xpb:
        return "php-fpm"
    if "php/" in xpb:
        if "apache" in s:
            return "mod_php (probable)"
        if "nginx" in s:
            return "php-fpm (probable)"
    return ""


def _detect_mpm(host: str, port: int, path: str, tls: bool) -> str:
    try:
        t0 = time.monotonic()
        socks = []
        for _ in range(3):
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            )
            socks.append(s)
        for s in socks:
            try:
                s.recv(4096)
            except OSError:
                pass
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        elapsed = time.monotonic() - t0
        if elapsed > 2.0:
            return "prefork (single-worker behavior)"
    except OSError:
        pass
    return ""


def _probe_upload_progress(host: str, port: int, path: str,
                           tls: bool) -> str:
    status, headers, _ = _post_multipart(host, port, path, tls, [
        ("PHP_SESSION_UPLOAD_PROGRESS", "probe_recon", None),
        ("upload", "", b"X" * 256),
    ])
    if status == 0:
        return "unreachable"
    if "PHPSESSID" in headers.get("set-cookie", ""):
        return "ACTIVE (session cookie set on probe)"

    status2, headers2, _ = _post_multipart(host, port, path, tls, [
        ("PHPSESSID", "reconprobe000000000000000000000000", None),
        ("PHP_SESSION_UPLOAD_PROGRESS", "probe_recon", None),
        ("upload", "", b"X" * 256),
    ])
    if "PHPSESSID" in headers2.get("set-cookie", ""):
        return "ACTIVE (session started via form field + progress)"
    return "inactive or hidden"


def fingerprint(host: str, port: int, path: str = "/",
                tls: bool = False, timeout: float = 10) -> TargetInfo:
    info = TargetInfo(
        url=f"{'https' if tls else 'http'}://{host}:{port}{path}"
    )

    status, headers, body = _get(host, port, path, tls, timeout)
    if status == 0:
        log.field("probe GET /", "connection failed", status="fail")
        return info

    log.field("probe GET /", f"HTTP {status}")
    log.field("probe headers", f"{len(headers)} received")
    info.reachable = True
    info.raw_headers = headers

    server = headers.get("server", "")
    xpb = headers.get("x-powered-by", "")
    info.server = server

    php_str = ""
    if "PHP/" in xpb:
        php_str = xpb
    elif "PHP/" in server:
        php_str = server
    if php_str:
        m = re.search(r"PHP/[\d.]+", php_str)
        info.php_version = m.group() if m else php_str
        info.php_version_tuple = _parse_php_version(php_str)
        log.field("PHP version",
                  f"{'.'.join(map(str, info.php_version_tuple)) or info.php_version}")
    else:
        log.field("PHP version", "hidden", status="warn")
        info.notes.append("PHP version hidden")
        _, hd2, bd2 = _get(host, port, path + "?=" + "A" * 2000, tls, timeout)
        for src in (hd2.get("x-powered-by", ""),
                    bd2.decode("latin1", "replace")):
            if "PHP/" in src:
                m = re.search(r"PHP/[\d.]+", src)
                if m:
                    info.php_version = m.group()
                    info.php_version_tuple = _parse_php_version(src)
                    log.field("PHP version (extracted)",
                              f"{'.'.join(map(str, info.php_version_tuple))}")
                    break

    if server:
        log.field("server", server)
    info.os_hint = _detect_os(server, headers, body)
    if info.os_hint:
        log.field("OS hint", info.os_hint)

    info.sapi = _detect_sapi(server, headers)
    log.field("SAPI", info.sapi or "unknown",
              status="ok" if info.sapi else "warn")

    if "apache" in server.lower() or "mod_php" in info.sapi:
        info.mpm = _detect_mpm(host, port, path, tls)
        if info.mpm:
            log.field("MPM", info.mpm)

    info.upload_progress = _probe_upload_progress(host, port, path, tls)
    log.field("upload_progress", info.upload_progress,
              status="ok" if "ACTIVE" in info.upload_progress else "warn")

    if info.php_version_tuple:
        major_minor = info.php_version_tuple[:2]
        patch_ver = PATCHED_VERSIONS.get(major_minor)
        if major_minor < (8, 2):
            info.vulnerable = True
            info.vulns.append(f"PHP {info.php_version} — EOL, no patch")
            log.field("patch check",
                      f"{info.php_version} EOL", status="warn")
        elif patch_ver and info.php_version_tuple < patch_ver:
            info.vulnerable = True
            pv = ".".join(str(x) for x in patch_ver)
            info.vulns.append(
                f"PHP {info.php_version} < {pv} — CVE-2026-109618/619 affected"
            )
            log.field("patch check",
                      f"{info.php_version} < {pv} vulnerable")
        elif patch_ver and info.php_version_tuple >= patch_ver:
            log.field("patch check",
                      f"{info.php_version} >= "
                      f"{'.'.join(str(x) for x in patch_ver)} patched",
                      status="warn")

    if "ACTIVE" in info.upload_progress:
        info.vulns.append(
            "session.upload_progress.enabled = On (attack vector active)"
        )

    log.field("vulnerable",
              "YES" if info.vulnerable else "NO",
              status="ok" if info.vulnerable else "fail")
    for v in info.vulns:
        log.warn(v)

    return info
