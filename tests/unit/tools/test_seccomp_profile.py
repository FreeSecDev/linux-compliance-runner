from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Final, cast

import pytest

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
PROFILE: Final[Path] = REPOSITORY_ROOT / "tools" / "image" / "seccomp-buildah.json"
ADDED: Final[list[str]] = [
    "clone",
    "clone3",
    "mount",
    "pivot_root",
    "setns",
    "umount",
    "umount2",
    "unshare",
]
DOCKER_DEFAULT_WITHOUT_ADDED: Final[str] = (
    "1b02899792b96afffc0ccab613fffc48857228c50a2b160393ffa941b817f81b"
)
GRANTED_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_CHROOT"}
)
STILL_BLOCKED: Final[list[str]] = [
    "add_key",
    "bpf",
    "delete_module",
    "finit_module",
    "fsopen",
    "init_module",
    "io_uring_enter",
    "io_uring_setup",
    "kexec_file_load",
    "kexec_load",
    "keyctl",
    "mount_setattr",
    "move_mount",
    "open_by_handle_at",
    "perf_event_open",
    "request_key",
    "userfaultfd",
]


def entries() -> list[dict[str, Any]]:
    profile = cast("dict[str, Any]", json.loads(PROFILE.read_text(encoding="utf-8")))
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    return cast("list[dict[str, Any]]", profile["syscalls"])


def reachable(entry: dict[str, Any]) -> bool:
    if entry["action"] != "SCMP_ACT_ALLOW":
        return False
    capabilities = set(cast("dict[str, Any]", entry.get("includes") or {}).get("caps", []))
    return not capabilities or bool(capabilities & GRANTED_CAPABILITIES)


def test_the_profile_adds_exactly_the_namespace_and_mount_syscalls_once() -> None:
    found = entries()
    added = [entry for entry in found if entry["names"] == ADDED]
    assert len(added) == 1
    [entry] = added
    assert entry["action"] == "SCMP_ACT_ALLOW"
    assert set(entry) == {"names", "action", "comment"}
    for other in found:
        if other is not entry:
            assert not set(other["names"]) & set(ADDED), other


@pytest.mark.parametrize("syscall", STILL_BLOCKED)
def test_the_profile_keeps_dangerous_syscalls_out_of_reach(syscall: str) -> None:
    for entry in entries():
        if syscall in entry["names"]:
            assert not reachable(entry), (syscall, entry)


def test_chroot_is_reachable_only_through_the_granted_sys_chroot_capability() -> None:
    [entry] = [entry for entry in entries() if "chroot" in entry["names"]]
    assert entry["includes"] == {"caps": ["CAP_SYS_CHROOT"]}


def test_everything_but_the_added_entry_is_dockers_default_profile() -> None:
    profile = cast("dict[str, Any]", json.loads(PROFILE.read_text(encoding="utf-8")))
    profile["syscalls"] = [entry for entry in profile["syscalls"] if entry["names"] != ADDED]
    canonical = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(canonical).hexdigest() == DOCKER_DEFAULT_WITHOUT_ADDED
