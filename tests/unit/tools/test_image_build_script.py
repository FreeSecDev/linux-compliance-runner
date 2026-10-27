from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
SCRIPT: Final[Path] = REPOSITORY_ROOT / "tools" / "image" / "buildah.sh"
BASH: Final[str] = shutil.which("bash") or "/bin/bash"
INSTALL: Final[str] = shutil.which("install") or "/usr/bin/install"
COMMIT: Final[str] = "0123456789abcdef0123456789abcdef01234567"
ARCHIVE_BYTES: Final[bytes] = b"docker-archive bytes\n"
BUILD_USER_ENVIRONMENT: Final[list[str]] = sorted(
    [
        "BUILDAH_ISOLATION",
        "CONTAINERS_REGISTRIES_CONF",
        "CONTAINERS_STORAGE_CONF",
        "HOME",
        "PATH",
        "REGISTRY_AUTH_FILE",
        "XDG_RUNTIME_DIR",
    ]
)

FAKE_BUILDAH: Final[str] = """
import json, os, sys
from pathlib import Path
state = Path(__file__).resolve().parent.parent
def read(name, default=""):
    path = state / name
    return path.read_text(encoding="utf-8") if path.exists() else default
arguments = sys.argv[1:]
with (state / "calls.jsonl").open("a", encoding="utf-8") as log:
    names = sorted(name for name in os.environ if name != "LC_CTYPE")
    log.write(json.dumps({"argv": arguments, "env": names}) + "\\n")
command = arguments[0]
if command == "--version":
    print(read("version.txt", "buildah version 1.43.5 (image-spec 1.1.1, runtime-spec 1.2.1)"))
elif command == "info":
    print(read("rootless.txt", "true"))
elif command == "build":
    sys.exit(int(read("build-status.txt", "0")))
elif command == "inspect":
    print(read("revision.txt"))
elif command == "push":
    transport, target, reference = arguments[-1].split(":", 2)
    assert transport == "docker-archive", arguments
    assert reference == "localhost/linux-compliance-runner:build", arguments
    Path(target).write_bytes(read("archive.txt").encode())
else:
    sys.exit(f"unexpected buildah call {arguments}")
"""
FAKE_RUNUSER: Final[str] = """
import os, sys
arguments = sys.argv[1:]
assert arguments[:2] == ["-u", "build"], arguments
separator = arguments.index("--")
os.execvp(arguments[separator + 1], arguments[separator + 1:])
"""
FAKE_INSTALL: Final[str] = f"""
import os, sys
arguments = sys.argv[1:]
kept = []
skip = False
for argument in arguments:
    if skip:
        skip = False
        continue
    if argument in ("-o", "-g"):
        skip = True
        continue
    kept.append(argument)
os.execv({INSTALL!r}, [{INSTALL!r}, *kept])
"""
FAKE_ID: Final[str] = """
import sys
sys.exit(0 if sys.argv[1:] == ["-u", "build"] else 1)
"""
FAKE_CHOWN: Final[str] = "import sys\n"
FAKE_UNAME: Final[str] = "print('x86_64')\n"


def write_tool(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def fake(tmp_path: Path) -> Path:
    tools = tmp_path / "bin"
    tools.mkdir()
    for name, body in (
        ("buildah", FAKE_BUILDAH),
        ("runuser", FAKE_RUNUSER),
        ("install", FAKE_INSTALL),
        ("id", FAKE_ID),
        ("chown", FAKE_CHOWN),
        ("uname", FAKE_UNAME),
    ):
        write_tool(tools, name, body)
    source = tmp_path / "source"
    (source / "toolbox").mkdir(parents=True)
    (source / "Containerfile").write_text("FROM scratch\n", encoding="utf-8")
    (source / "Containerfile.dockerignore").write_text("*\n", encoding="utf-8")
    (source / "toolbox" / "uv.lock").write_text("lock\n", encoding="utf-8")
    (tmp_path / "revision.txt").write_text(COMMIT, encoding="utf-8")
    (tmp_path / "archive.txt").write_bytes(ARCHIVE_BYTES)
    return tmp_path


def run(fake: Path, command: str, **overrides: str) -> subprocess.CompletedProcess[bytes]:
    path = f"{fake / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}"
    environment = {
        "PATH": path,
        "IMAGE_BUILD_WORK": str(fake / "work"),
        "IMAGE_BUILD_STORE": str(fake / "store"),
        "IMAGE_BUILD_SOURCE": str(fake / "source"),
        "IMAGE_BUILD_PATH": path,
        "EXPECTED_BUILDAH_VERSION": "1.43.5",
        "EXPECTED_COMMIT": COMMIT,
        "BUILD_DATE": "2026-10-27T06:00:00Z",
        "GH_TOKEN": "must-not-reach-buildah",
    }
    environment.update(overrides)
    return subprocess.run(
        [BASH, str(SCRIPT), command],
        capture_output=True,
        check=False,
        timeout=60,
        env=environment,
    )


def calls(fake: Path) -> list[dict[str, list[str]]]:
    lines = (fake / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def build_user_environments(fake: Path) -> list[list[str]]:
    return [call["env"] for call in calls(fake) if "BUILDAH_ISOLATION" in call["env"]]


def buildah_call(fake: Path, command: str) -> list[str]:
    [found] = [call["argv"] for call in calls(fake) if call["argv"][0] == command]
    return found


def test_build_runs_rootless_buildah_on_the_archived_commit(fake: Path) -> None:
    result = run(fake, "build")
    assert result.returncode == 0, result.stderr.decode()
    arguments = buildah_call(fake, "build")
    context = str(fake / "work" / "context")
    for expected in (
        "--isolation",
        "--layers=false",
        "--pull=always",
        f"VCS_REF={COMMIT}",
        "BUILD_DATE=2026-10-27T06:00:00Z",
        "localhost/linux-compliance-runner:build",
    ):
        assert expected in arguments
    assert arguments[arguments.index("--format") + 1] == "docker"
    assert arguments[arguments.index("--target") + 1] == "toolbox"
    assert arguments[-1] == context
    assert (fake / "work" / "context" / "toolbox" / "uv.lock").is_file()
    storage = (fake / "work" / "config" / "storage.conf").read_text(encoding="utf-8")
    assert f'graphroot = "{fake / "store" / "graph"}"' in storage
    assert 'driver = "overlay"' in storage
    assert "mount_program" not in storage
    assert "fuse" not in storage
    auth = (fake / "work" / "config" / "auth.json").read_text(encoding="utf-8")
    assert auth == '{"auths": {}}\n'
    assert result.stdout == b""
    registries = (fake / "work" / "config" / "registries.conf").read_text(encoding="utf-8")
    assert "unqualified-search-registries = []" in registries
    assert build_user_environments(fake) == [BUILD_USER_ENVIRONMENT] * 3
    assert "with Buildah 1.43.5" in result.stderr.decode()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"EXPECTED_COMMIT": COMMIT[:12]}, "EXPECTED_COMMIT must be a full commit SHA"),
        ({"EXPECTED_COMMIT": COMMIT.upper()}, "EXPECTED_COMMIT must be a full commit SHA"),
        ({"BUILD_DATE": "2026-10-27 06:00"}, "BUILD_DATE must be a UTC RFC 3339 time"),
        ({"EXPECTED_BUILDAH_VERSION": "latest"}, "EXPECTED_BUILDAH_VERSION must be x.y.z"),
        ({"EXPECTED_BUILDAH_VERSION": "1.43.6"}, "unexpected builder: buildah version 1.43.5"),
    ],
)
def test_build_refuses_invalid_inputs(fake: Path, overrides: dict[str, str], message: str) -> None:
    result = run(fake, "build", **overrides)
    assert result.returncode == 1
    assert message in result.stderr.decode()


def test_build_refuses_a_missing_source(fake: Path) -> None:
    (fake / "source" / "Containerfile").unlink()
    result = run(fake, "build")
    assert result.returncode == 1
    assert "must hold the archived commit" in result.stderr.decode()


def test_build_refuses_a_builder_that_is_not_rootless(fake: Path) -> None:
    (fake / "rootless.txt").write_text("false", encoding="utf-8")
    result = run(fake, "build")
    assert result.returncode == 1
    assert "Buildah is not running rootless" in result.stderr.decode()
    assert "build" not in [call["argv"][0] for call in calls(fake)]


def test_build_refuses_an_image_with_another_revision_label(fake: Path) -> None:
    (fake / "revision.txt").write_text("f" * 40, encoding="utf-8")
    result = run(fake, "build")
    assert result.returncode == 1
    assert f"carries revision {'f' * 40}, expected {COMMIT}" in result.stderr.decode()


def test_build_fails_when_buildah_fails(fake: Path) -> None:
    (fake / "build-status.txt").write_text("3", encoding="utf-8")
    result = run(fake, "build")
    assert result.returncode == 3
    assert "inspect" not in [call["argv"][0] for call in calls(fake)]


def test_export_writes_only_the_docker_archive_to_stdout(fake: Path) -> None:
    result = run(fake, "export")
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == ARCHIVE_BYTES
    push = buildah_call(fake, "push")
    assert push[-2] == "localhost/linux-compliance-runner:build"
    assert push[-1].startswith("docker-archive:")
    assert not (fake / "work" / "export" / "image.tar").exists()
    assert "build" not in [call["argv"][0] for call in calls(fake)]
    assert build_user_environments(fake) == [BUILD_USER_ENVIRONMENT] * 2


def test_export_refuses_an_image_with_another_revision_label(fake: Path) -> None:
    (fake / "revision.txt").write_text("f" * 40, encoding="utf-8")
    result = run(fake, "export")
    assert result.returncode == 1
    assert result.stdout == b""
    assert "push" not in [call["argv"][0] for call in calls(fake)]


def test_export_refuses_an_empty_archive(fake: Path) -> None:
    (fake / "archive.txt").write_bytes(b"")
    result = run(fake, "export")
    assert result.returncode == 1
    assert result.stdout == b""
    assert "buildah wrote no archive" in result.stderr.decode()


def test_export_refuses_an_invalid_commit(fake: Path) -> None:
    result = run(fake, "export", EXPECTED_COMMIT="main")
    assert result.returncode == 1
    assert "EXPECTED_COMMIT must be a full commit SHA" in result.stderr.decode()


@pytest.mark.parametrize("arguments", [[], ["build", "export"], ["push"]])
def test_usage_errors_exit_with_status_two(fake: Path, arguments: list[str]) -> None:
    result = subprocess.run(
        [BASH, str(SCRIPT), *arguments],
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
        env={"PATH": f"{fake / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}"},
    )
    assert result.returncode == 2
    assert "usage:" in result.stderr
