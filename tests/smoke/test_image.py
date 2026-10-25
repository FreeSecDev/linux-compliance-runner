"""Runtime smoke tests for the toolbox image.

The image under test comes from the ``SMOKE_IMAGE`` environment variable and is
started with the hardening flags the release gate requires: read-only root file
system, no capabilities, no new privileges, UID 10001, no network, tmpfs scratch.
``make image-smoke`` builds ``localhost/linux-compliance-runner:smoke`` and runs
this module; without ``SMOKE_IMAGE`` every test is skipped.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

IMAGE: Final[str | None] = os.environ.get("SMOKE_IMAGE")
ENGINE: Final[str] = os.environ.get("SMOKE_ENGINE", "docker")
REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SAMPLE_COLLECTION: Final[Path] = Path(__file__).resolve().parent / "sample_collection"
TIMEOUT_SECONDS: Final[int] = 300
BUILD_TIMEOUT_SECONDS: Final[int] = 900
BUILD_DATE_REJECTED: Final[re.Pattern[str]] = re.compile(
    r"^(?:#\d+ \d+\.\d+ )?BUILD_DATE (?:must be an RFC 3339|build argument is required)",
    re.MULTILINE,
)
EXPECTED_ID: Final[int] = 10001

pytestmark = pytest.mark.skipif(IMAGE is None, reason="SMOKE_IMAGE is not set")

CONTAINERFILE: Final[str] = (REPOSITORY_ROOT / "Containerfile").read_text(encoding="utf-8")
LOCKED_PACKAGES: Final[dict[str, str]] = {
    package["name"]: package["version"]
    for package in tomllib.loads(
        (REPOSITORY_ROOT / "toolbox" / "uv.lock").read_text(encoding="utf-8")
    )["package"]
}


def python_pin(package: str) -> str:
    assert package in LOCKED_PACKAGES, f"{package} is not in toolbox/uv.lock"
    return LOCKED_PACKAGES[package]


def apk_pin(package: str) -> str:
    match = re.search(rf"^\s+{re.escape(package)}=(\S+?)(?: \\)?$", CONTAINERFILE, re.MULTILINE)
    assert match, f"{package} is not pinned with apk in the Containerfile"
    return re.sub(r"-r\d+$", "", match.group(1)).replace("_p", "p")


def containerfile_arg(name: str) -> str:
    match = re.search(rf"^ARG {re.escape(name)}=(\S+)$", CONTAINERFILE, re.MULTILINE)
    assert match, f"ARG {name} is missing from the Containerfile"
    return match.group(1)


@dataclass(frozen=True)
class Tool:
    """A bundled tool, the command that prints its version and the version it must report."""

    name: str
    command: tuple[str, ...]
    expected_version: str


TOOLS: Final[tuple[Tool, ...]] = (
    Tool("ansible-core", ("ansible", "--version"), python_pin("ansible-core")),
    Tool("ansible-galaxy", ("ansible-galaxy", "--version"), python_pin("ansible-core")),
    Tool("ansible-lint", ("ansible-lint", "--version"), python_pin("ansible-lint")),
    Tool(
        "antsibull-changelog",
        ("antsibull-changelog", "--version"),
        python_pin("antsibull-changelog"),
    ),
    Tool("bandit", ("bandit", "--version"), python_pin("bandit")),
    Tool("checkov", ("checkov", "--version"), python_pin("checkov")),
    Tool("coverage", ("coverage", "--version"), python_pin("coverage")),
    Tool("hadolint", ("hadolint", "--version"), python_pin("hadolint-bin")),
    Tool("molecule", ("molecule", "--version"), python_pin("molecule")),
    Tool("mypy", ("mypy", "--version"), python_pin("mypy")),
    Tool("pylint", ("pylint", "--version"), python_pin("pylint")),
    Tool("pyright", ("pyright", "--version"), python_pin("pyright")),
    Tool("pytest", ("pytest", "--version"), python_pin("pytest")),
    Tool("ruff", ("ruff", "--version"), python_pin("ruff")),
    Tool("yamllint", ("yamllint", "--version"), python_pin("yamllint")),
    Tool("zizmor", ("zizmor", "--version"), python_pin("zizmor")),
    Tool("python", ("python", "--version"), containerfile_arg("PYTHON_VERSION")),
    Tool("opentofu", ("tofu", "version"), containerfile_arg("OPENTOFU_VERSION")),
    Tool("actionlint", ("actionlint", "-version"), apk_pin("actionlint")),
    Tool("bash", ("bash", "--version"), apk_pin("bash")),
    Tool("git", ("git", "--version"), apk_pin("git")),
    Tool("jq", ("jq", "--version"), apk_pin("jq")),
    Tool("make", ("make", "--version"), apk_pin("make")),
    Tool("node", ("node", "--version"), apk_pin("nodejs")),
    Tool("openssh-client", ("ssh", "-V"), apk_pin("openssh-client-default")),
    Tool("shellcheck", ("shellcheck", "--version"), apk_pin("shellcheck")),
    Tool("uv", ("uv", "--version"), apk_pin("uv")),
)


def run_in_image(
    *command: str,
    volumes: tuple[str, ...] = (),
    user: str = str(EXPECTED_ID),
) -> subprocess.CompletedProcess[str]:
    assert IMAGE is not None
    arguments = [
        ENGINE,
        "run",
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        user,
        "--network=none",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        f"/home/toolbox:uid={EXPECTED_ID},gid={EXPECTED_ID},mode=0700",
    ]
    for volume in volumes:
        arguments.extend(["--volume", volume])
    arguments.extend([IMAGE, *command])
    return subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_SECONDS,
    )


def shell(
    script: str,
    *,
    volumes: tuple[str, ...] = (),
    user: str = str(EXPECTED_ID),
) -> subprocess.CompletedProcess[str]:
    return run_in_image("/bin/sh", "-c", script, volumes=volumes, user=user)


@pytest.mark.parametrize("tool", TOOLS, ids=lambda tool: tool.name)
def test_tool_reports_pinned_version(tool: Tool) -> None:
    result = run_in_image(*tool.command)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert tool.expected_version in output, output


def test_effective_identity_is_toolbox_10001() -> None:
    result = run_in_image("id")
    assert result.returncode == 0, result.stderr
    assert f"uid={EXPECTED_ID}(toolbox)" in result.stdout
    assert f"gid={EXPECTED_ID}(toolbox)" in result.stdout
    assert shell("id -u").stdout.strip() == str(EXPECTED_ID)


def test_image_metadata_declares_user_and_workdir() -> None:
    assert IMAGE is not None
    inspected = subprocess.run(
        [ENGINE, "image", "inspect", IMAGE],
        capture_output=True,
        text=True,
        check=True,
        timeout=TIMEOUT_SECONDS,
    )
    config = json.loads(inspected.stdout)[0]["Config"]
    assert config["User"] == f"{EXPECTED_ID}:{EXPECTED_ID}"
    assert config["WorkingDir"] == "/work"
    assert config.get("ExposedPorts") in (None, {})
    assert config.get("Entrypoint") in (None, [])


def test_oci_labels_are_set() -> None:
    assert IMAGE is not None
    inspected = subprocess.run(
        [ENGINE, "image", "inspect", IMAGE],
        capture_output=True,
        text=True,
        check=True,
        timeout=TIMEOUT_SECONDS,
    )
    labels = json.loads(inspected.stdout)[0]["Config"]["Labels"]
    required = (
        "org.opencontainers.image.title",
        "org.opencontainers.image.description",
        "org.opencontainers.image.source",
        "org.opencontainers.image.licenses",
        "org.opencontainers.image.version",
        "org.opencontainers.image.revision",
        "org.opencontainers.image.created",
        "org.opencontainers.image.base.name",
    )
    for label in required:
        assert labels.get(label), f"missing OCI label {label}"
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", labels["org.opencontainers.image.created"]
    )
    assert labels["org.opencontainers.image.source"] == (
        "https://github.com/FreeSecDev/linux-compliance-runner"
    )


@pytest.mark.parametrize(
    "build_date",
    [
        "",
        "2026-10-25",
        "2026-10-25 21:27:04Z",
        "2026-10-25T24:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-10-25T21:27:04",
        "2026-10-25T21:27:04Z\n2026",
        "yesterday",
    ],
    ids=repr,
)
def test_build_rejects_a_build_date_that_is_not_rfc_3339(build_date: str) -> None:
    progress = ["--progress=plain"] if ENGINE == "docker" else []
    result = subprocess.run(
        [
            ENGINE,
            "build",
            *progress,
            "--file",
            str(REPOSITORY_ROOT / "Containerfile"),
            "--target",
            "toolbox",
            "--build-arg",
            f"BUILD_DATE={build_date}",
            str(REPOSITORY_ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert BUILD_DATE_REJECTED.search(output), output


def test_no_setuid_or_setgid_files() -> None:
    result = shell(
        r"find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print; true",
        user="0",
    )
    assert result.stderr.strip() == ""
    assert result.stdout.strip() == ""


def test_no_ssh_daemon() -> None:
    result = shell(
        "command -v sshd && exit 1; "
        "find / -xdev \\( -name 'sshd*' -o -name 'ssh-keysign' \\) -print; true",
        user="0",
    )
    assert result.stderr.strip() == ""
    assert result.stdout.strip() == ""
    assert shell("test -e /etc/ssh/sshd_config").returncode != 0
    assert run_in_image("ssh", "-V").returncode == 0


def test_root_file_system_is_read_only() -> None:
    result = shell("touch /usr/smoke-write-test")
    assert result.returncode != 0
    assert "Read-only file system" in result.stderr


def test_home_and_caches_are_writable_on_tmpfs() -> None:
    script = (
        'set -e; test "$HOME" = /home/toolbox; '
        'touch "$HOME/smoke"; '
        'for dir in "$UV_CACHE_DIR" "$XDG_CACHE_HOME" "$PRE_COMMIT_HOME" "$ANSIBLE_HOME" '
        '"$ANSIBLE_LOCAL_TEMP"; do mkdir -p "$dir"; touch "$dir/smoke"; done; '
        "touch /tmp/smoke; echo writable"
    )
    result = shell(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "writable"


def test_ruff_and_pyright_run_without_network_or_writable_root() -> None:
    script = (
        "set -e; printf 'x: int = 1\\n' > /tmp/sample.py; "
        "ruff check --no-cache /tmp/sample.py; pyright /tmp/sample.py"
    )
    result = shell(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 errors" in result.stdout


def test_tofu_formats_a_sample_without_network() -> None:
    script = (
        "set -e; printf 'variable \"x\" {\\n  type = string\\n}\\n' > /tmp/main.tf; "
        "tofu fmt -check /tmp/main.tf"
    )
    result = shell(script)
    assert result.returncode == 0, result.stdout + result.stderr


def test_ansible_galaxy_collection_build_on_sample() -> None:
    result = shell(
        "set -e; ansible-galaxy collection build /work --output-path /tmp/build --force; "
        "ls /tmp/build",
        volumes=(f"{SAMPLE_COLLECTION}:/work:ro",),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "freesecdev-smoke-1.0.0.tar.gz" in result.stdout


def test_no_credentials_in_environment_or_files() -> None:
    environment = run_in_image("env").stdout
    for name in re.findall(r"^([A-Za-z0-9_]+)=", environment, re.MULTILINE):
        assert not re.search(r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|AWS_", name), name
    script = (
        "find / -xdev -path '*/site-packages' -prune -o "
        "\\( -name '.netrc' -o -name '.git-credentials' -o -name 'id_rsa*' "
        "-o -name 'id_ed25519*' -o -name '.pypirc' -o -name '.npmrc' -o -name 'credentials' "
        "-o -name '.docker' -o -name '.aws' \\) -print; true"
    )
    result = shell(script, user="0")
    assert result.stderr.strip() == ""
    assert result.stdout.strip() == ""


def test_python_tree_is_pruned() -> None:
    result = shell("ls /opt/python/bin; ls /opt/python/lib/python3.12/site-packages")
    assert result.returncode == 0, result.stderr
    assert "pip" not in result.stdout
    assert "idle" not in result.stdout
