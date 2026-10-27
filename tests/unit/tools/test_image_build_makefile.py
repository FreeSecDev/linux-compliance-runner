from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any, Final, cast

import pytest

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
MAKEFILE: Final[Path] = REPOSITORY_ROOT / "Makefile"
RENOVATE: Final[Path] = REPOSITORY_ROOT / ".renovaterc.json"
MAKE: Final[str | None] = shutil.which("make")
GIT: Final[str | None] = shutil.which("git")
TRUE: Final[str] = shutil.which("true") or "/bin/true"
BUILDER: Final[str] = "quay.io/buildah/stable"
DIGEST: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}")
RELEASE: Final[str] = "ghcr.io/freesecdev/linux-compliance-runner"
RELEASE_TAG: Final[str] = "0123456789abcdef0123456789abcdef01234567-12-1"
AWS_TEXT: Final[re.Pattern[str]] = re.compile(
    r"\baws\b|AWS_|amazonaws|codebuild|\bECR\b|staging", re.IGNORECASE
)
WORKFLOW_ENVIRONMENT: Final[dict[str, str]] = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_WORKFLOW_REF": (
        "FreeSecDev/linux-compliance-runner/.github/workflows/image-build.yml@refs/heads/main"
    ),
}
FAKE_CRANE: Final[str] = """
import os, sys
sys.stderr.write(os.environ.get("FAKE_CRANE_OUTPUT", ""))
sys.exit(int(os.environ.get("FAKE_CRANE_STATUS", "1")))
"""
FAKE_ENGINE: Final[str] = """
import os, sys
if sys.argv[1:3] == ["image", "inspect"]:
    print(os.environ["FAKE_REVISION"])
"""


def variables() -> dict[str, str]:
    found: dict[str, str] = {}
    for line in MAKEFILE.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*) := (.*)", line)
        if match is not None:
            found[match.group(1)] = match.group(2)
    return found


def recipe(target: str) -> str:
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(target)}:.*\n((?:\t.*\n)+)", text, re.MULTILINE)
    assert match is not None, target
    return match.group(0)


def python_pattern(renovate: str) -> re.Pattern[str]:
    return re.compile(renovate.replace("(?<", "(?P<"))


def builder_manager() -> dict[str, Any]:
    config = cast("dict[str, Any]", json.loads(RENOVATE.read_text(encoding="utf-8")))
    managers = [
        manager
        for manager in cast("list[dict[str, Any]]", config["customManagers"])
        if manager.get("datasourceTemplate") == "docker"
    ]
    assert len(managers) == 1
    return managers[0]


def head() -> str:
    assert GIT is not None
    completed = subprocess.run(
        [GIT, "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip()


def tool(directory: Path, name: str, body: str) -> str:
    path = directory / name
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def run_make(
    *arguments: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    assert MAKE is not None
    return subprocess.run(
        [MAKE, "--no-print-directory", "-s", "-C", str(REPOSITORY_ROOT), *arguments],
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(Path.home()),
            **(environment or {}),
        },
    )


def archive(
    path: Path, revision: str, entries: int = 1, named: str | None = None
) -> tuple[str, str]:
    config = json.dumps({"config": {"Labels": {"org.opencontainers.image.revision": revision}}})
    config_bytes = config.encode()
    config_name = hashlib.sha256(config_bytes).hexdigest() + ".json"
    listed = config_name if named is None else named
    manifest = json.dumps([{"Config": listed, "Layers": []}] * entries).encode()
    members = [("manifest.json", manifest), (config_name, config_bytes)]
    if named is not None and not named.startswith("-"):
        members.append((named, config_bytes))
    with tarfile.open(path, "w") as handle:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            handle.addfile(info, io.BytesIO(data))
    return (
        hashlib.sha256(path.read_bytes()).hexdigest(),
        "sha256:" + hashlib.sha256(config_bytes).hexdigest(),
    )


def test_the_builder_image_is_pinned_by_digest_and_its_tag() -> None:
    found = variables()
    assert found["BUILDAH_IMAGE"] == BUILDER
    assert re.fullmatch(r"v\d+\.\d+\.\d+-immutable", found["BUILDAH_TAG"])
    assert DIGEST.fullmatch(found["BUILDAH_DIGEST"])
    assert found["BUILDAH_REFERENCE"] == "$(BUILDAH_IMAGE)@$(BUILDAH_DIGEST)"
    assert found["BUILDAH_VERSION"] == "$(patsubst v%-immutable,%,$(BUILDAH_TAG))"


def test_renovate_tracks_the_builder_digest_and_tag_together() -> None:
    manager = builder_manager()
    assert manager["managerFilePatterns"] == ["/(^|/)Makefile$/"]
    found = variables()
    [pattern] = manager["matchStrings"]
    matches = list(python_pattern(pattern).finditer(MAKEFILE.read_text(encoding="utf-8")))
    assert len(matches) == 1
    assert matches[0].group("depName") == BUILDER
    assert matches[0].group("currentValue") == found["BUILDAH_TAG"]
    assert matches[0].group("currentDigest") == found["BUILDAH_DIGEST"]
    versioning = manager["versioningTemplate"].removeprefix("regex:")
    version = python_pattern(versioning).fullmatch(found["BUILDAH_TAG"])
    assert version is not None
    assert version.group("major") == "1"


def test_renovate_no_longer_tracks_the_codebuild_inputs() -> None:
    text = RENOVATE.read_text(encoding="utf-8")
    assert "codebuild" not in text
    assert "amazon-ecr-credential-helper" not in text


def test_the_makefile_has_no_aws_build_path() -> None:
    text = MAKEFILE.read_text(encoding="utf-8").replace("aws-infrastructure", "")
    assert AWS_TEXT.search(text) is None
    assert not (REPOSITORY_ROOT / "codebuild").exists()
    assert not (REPOSITORY_ROOT / "tools" / "aws").exists()


def test_the_builder_runs_with_the_checked_in_confinement() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    run = text[text.index("BUILDAH_RUN = ") : text.index("RELEASE_REGISTRY := ")]
    assert "--privileged" not in text
    assert "seccomp=unconfined" not in text
    assert "/dev/fuse" not in text
    assert "--cap-drop ALL $(foreach cap,$(BUILDAH_CAPABILITIES),--cap-add $(cap))" in run
    capabilities = "CHOWN DAC_OVERRIDE FOWNER SETUID SETGID SYS_CHROOT"
    assert variables()["BUILDAH_CAPABILITIES"] == capabilities
    assert "--security-opt 'seccomp=$(CURDIR)/$(IMAGE_BUILD_DIR)/seccomp-buildah.json'" in run
    assert "--security-opt apparmor=unconfined" in run
    assert "no-new-privileges" not in run
    assert ":ro'" in run
    assert variables()["BUILDAH_SECCOMP"] == "tools/image/seccomp-buildah.json"


def test_the_build_uses_only_the_archived_commit_and_exports_an_archive() -> None:
    build = recipe("image-build")
    assert "git archive --format=tar HEAD -- $(IMAGE_BUILD_SOURCES)" in build
    assert "git show HEAD:tools/image/buildah.sh" in build
    assert "git show HEAD:$(BUILDAH_SECCOMP)" in build
    assert "/source:ro'" in build
    assert "bash '$(BUILDAH_SCRIPT)' export > $(IMAGE_ARCHIVE)" in build
    assert "GH_TOKEN" not in build
    assert variables()["IMAGE_BUILD_SOURCES"] == "Containerfile Containerfile.dockerignore toolbox"


def test_the_push_checks_the_archive_registry_digest_config_and_label() -> None:
    push = recipe("image-push")
    assert push.startswith("image-push: require-image-workflow ")
    assert "$(REQUIRE_ARCHIVE_HASH)" in push
    assert "$(REQUIRE_ARCHIVE)" not in push
    assert "$(REQUIRE_ARCHIVE)" in recipe("image-archive-check")
    assert "release-tag-absent RELEASE_TAG=" in push
    assert push.index("release-tag-absent") < push.index("$(CRANE_RUN) push")
    assert "GITHUB_RUN_ATTEMPT" in push
    assert '"$$served" != "$$digest"' in push
    assert "'$(DOCKER_MANIFEST)'" in push
    assert '"$$config" != "$${EXPECTED_CONFIG_DIGEST}"' in push
    assert '"$$built" != "$$commit"' in push


def test_the_release_tag_is_set_only_after_verification_and_never_reused() -> None:
    release = recipe("image-release")
    assert release.startswith("image-release: require-image-workflow ")
    assert "verified.txt" in release
    assert release.index("release-tag-absent") < release.index("$(CRANE_RUN) tag")
    verify = recipe("verify-release")
    assert "--deny-self-hosted-runners" in verify
    assert '--source-digest "$(VERIFY_COMMIT)"' in verify
    assert '--signer-digest "$(VERIFY_COMMIT)"' in verify
    assert "--signer-workflow '$(RELEASE_WORKFLOW)@refs/heads/main'" in verify
    assert "gh --version" in verify
    assert '--certificate-github-workflow-sha "$(VERIFY_COMMIT)"' in verify


@pytest.mark.parametrize("target", ["image-push", "image-release"])
def test_publishing_targets_refuse_to_run_outside_the_workflow(target: str) -> None:
    result = run_make(target)
    assert result.returncode == 2
    assert "runs only in the image-build workflow on main" in result.stderr


def test_publishing_targets_refuse_another_workflow() -> None:
    environment = dict(WORKFLOW_ENVIRONMENT)
    environment["GITHUB_WORKFLOW_REF"] = environment["GITHUB_WORKFLOW_REF"].replace(
        "image-build.yml", "ci.yml"
    )
    result = run_make("image-push", environment=environment)
    assert result.returncode == 2
    assert "runs only in the image-build workflow on main" in result.stderr


@pytest.mark.parametrize(
    "reference",
    [
        f"{RELEASE}:latest",
        RELEASE,
        f"{RELEASE}@sha256:{'a' * 63}",
        f"{RELEASE}:v1@sha256:{'a' * 64}",
    ],
)
@pytest.mark.parametrize("target", ["image-pull", "image-smoke-pulled", "sbom-check"])
def test_registry_targets_refuse_anything_but_a_digest(target: str, reference: str) -> None:
    result = run_make(target, f"CONTAINER_ENGINE={TRUE}", environment={"IMAGE_REF": reference})
    assert result.returncode == 2
    assert "a digest reference, never a tag" in result.stderr


def test_the_build_refuses_another_commit() -> None:
    result = run_make(
        "image-build", f"CONTAINER_ENGINE={TRUE}", environment={"EXPECTED_COMMIT": "0" * 40}
    )
    assert result.returncode == 2
    assert f"but EXPECTED_COMMIT is {'0' * 40}" in result.stderr


@pytest.mark.parametrize(
    "case",
    [
        ("sha256:" + "a" * 64, 0, "", 1, "already exists; a release tag is never moved or reused"),
        (
            (
                "HEAD request failed: unexpected status code 404 Not Found\n"
                "Error: GET https://ghcr.io/v2/x/manifests/t: MANIFEST_UNKNOWN: manifest unknown\n"
            ),
            1,
            "",
            0,
            "does not exist yet",
        ),
        ("Error: GET https://ghcr.io/v2/x/manifests/t: NAME_UNKNOWN: unknown\n", 1, "", 0, "yet"),
        (
            (
                "HEAD request failed: unexpected status code 404 Not Found\n"
                "Error: GET https://ghcr.io/v2/x/manifests/t: unexpected status code 500\n"
            ),
            1,
            "",
            1,
            "could not prove that",
        ),
        ("Error: dial tcp: lookup ghcr.io: no such host\n", 1, "1", 1, "could not prove that"),
        (
            "Error: GET https://ghcr.io/token?scope=x&service=ghcr.io: DENIED: denied\n",
            1,
            "",
            1,
            "could not prove that",
        ),
        (
            "Error: GET https://ghcr.io/token?scope=x&service=ghcr.io: DENIED: denied\n",
            1,
            "1",
            0,
            "the package does not exist yet or the push fails next",
        ),
    ],
)
def test_the_release_tag_check_fails_closed(
    tmp_path: Path, case: tuple[str, int, str, int, str]
) -> None:
    output, status, allow_missing_package, returncode, message = case
    crane = tool(tmp_path, "crane", FAKE_CRANE)
    result = run_make(
        "release-tag-absent",
        f"CRANE={crane}",
        f"CRANE_RUN={crane}",
        f"ALLOW_MISSING_PACKAGE={allow_missing_package}",
        environment={
            "RELEASE_TAG": RELEASE_TAG,
            "FAKE_CRANE_OUTPUT": output,
            "FAKE_CRANE_STATUS": str(status),
        },
    )
    assert result.returncode == (2 if returncode else 0), result.stderr
    assert message in result.stdout + result.stderr


@pytest.mark.parametrize("tag", ["latest", f"{RELEASE_TAG[:-2]}", f"candidate-{RELEASE_TAG}"])
def test_the_release_tag_check_refuses_another_tag_shape(tmp_path: Path, tag: str) -> None:
    crane = tool(tmp_path, "crane", FAKE_CRANE)
    result = run_make(
        "release-tag-absent",
        f"CRANE={crane}",
        f"CRANE_RUN={crane}",
        environment={"RELEASE_TAG": tag},
    )
    assert result.returncode == 2
    assert "RELEASE_TAG must be <commit>-<run number>-<run attempt>" in result.stderr


def smoke_archive(
    tmp_path: Path, archive_sha256: str, config_digest: str, revision: str
) -> subprocess.CompletedProcess[str]:
    engine = tool(tmp_path, "engine", FAKE_ENGINE)
    return run_make(
        "image-smoke-archive",
        f"CONTAINER_ENGINE={engine}",
        f"RUN={TRUE}",
        f"IMAGE_ARCHIVE={tmp_path / 'image.tar'}",
        environment={
            "EXPECTED_ARCHIVE_SHA256": archive_sha256,
            "EXPECTED_CONFIG_DIGEST": config_digest,
            "FAKE_REVISION": revision,
        },
    )


def test_the_archive_is_accepted_only_with_the_recorded_hash_config_and_label(
    tmp_path: Path,
) -> None:
    archive_sha256, config_digest = archive(tmp_path / "image.tar", head())
    result = smoke_archive(tmp_path, archive_sha256, config_digest, head())
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("archive", "does not match EXPECTED_ARCHIVE_SHA256"),
        ("config", "the archived image config is not"),
        ("manifest", "manifest.json must name exactly one image whose config is"),
        ("format", "EXPECTED_ARCHIVE_SHA256 (64 hex) and EXPECTED_CONFIG_DIGEST"),
        ("label", "the archived image revision label is not the checked-out commit"),
        ("loaded", "the loaded image revision label"),
    ],
)
def test_the_archive_is_refused_when_anything_differs(
    tmp_path: Path, change: str, message: str
) -> None:
    revision = "f" * 40 if change == "label" else head()
    named = "0" * 64 + ".json" if change == "config" else None
    archive_sha256, config_digest = archive(tmp_path / "image.tar", revision, named=named)
    if change == "archive":
        archive_sha256 = "0" * 64
    if change in {"config", "manifest"}:
        config_digest = "sha256:" + "0" * 64
    if change == "format":
        config_digest = config_digest.removeprefix("sha256:")
    loaded = "f" * 40 if change == "loaded" else head()
    result = smoke_archive(tmp_path, archive_sha256, config_digest, loaded)
    assert result.returncode == 2
    assert message in result.stderr


def test_an_archive_with_several_images_is_refused(tmp_path: Path) -> None:
    archive_sha256, config_digest = archive(tmp_path / "image.tar", head(), entries=2)
    result = smoke_archive(tmp_path, archive_sha256, config_digest, head())
    assert result.returncode == 2
    assert "manifest.json must name exactly one image whose config is" in result.stderr


def test_every_archive_member_is_read_after_an_end_of_options_marker() -> None:
    lines = [
        line for line in MAKEFILE.read_text(encoding="utf-8").splitlines() if "tar -xOf" in line
    ]
    assert len(lines) == 6
    for line in lines:
        assert re.search(r"tar -xOf '\$\(IMAGE_ARCHIVE\)' -- ", line), line
    archive_check = MAKEFILE.read_text(encoding="utf-8")
    assert 'member="$${EXPECTED_CONFIG_DIGEST\\#sha256:}.json"' in archive_check
    assert "'$(CONFIG_MEMBER_PATTERN)'" in recipe("image-build")


@pytest.mark.parametrize(
    "named",
    [
        '--use-compress-program=sh -c "touch {marker}; cat"',
        "--to-command=touch {marker}",
        "../{digest}.json",
        "./{digest}.json",
        "{digest}.json.extra",
    ],
)
@pytest.mark.parametrize("target", ["image-archive-check", "image-smoke-archive"])
def test_a_crafted_config_member_is_refused_without_running_anything(
    tmp_path: Path, target: str, named: str
) -> None:
    marker = tmp_path / "PWNED"
    probe_sha256, probe_config = archive(tmp_path / "probe.tar", head())
    member = named.format(marker=marker, digest=probe_config.removeprefix("sha256:"))
    archive_sha256, config_digest = archive(tmp_path / "image.tar", head(), named=member)
    assert config_digest == probe_config
    assert archive_sha256 != probe_sha256
    engine = tool(tmp_path, "engine", FAKE_ENGINE)
    result = run_make(
        target,
        f"CONTAINER_ENGINE={engine}",
        f"RUN={TRUE}",
        f"IMAGE_ARCHIVE={tmp_path / 'image.tar'}",
        environment={
            "EXPECTED_ARCHIVE_SHA256": archive_sha256,
            "EXPECTED_CONFIG_DIGEST": config_digest,
            "FAKE_REVISION": head(),
        },
    )
    assert result.returncode == 2
    assert "manifest.json must name exactly one image whose config is" in result.stderr
    assert not marker.exists()


def test_the_missing_package_allowance_is_ignored_from_the_environment(tmp_path: Path) -> None:
    crane = tool(tmp_path, "crane", FAKE_CRANE)
    result = run_make(
        "release-tag-absent",
        f"CRANE={crane}",
        f"CRANE_RUN={crane}",
        environment={
            "RELEASE_TAG": RELEASE_TAG,
            "ALLOW_MISSING_PACKAGE": "1",
            "FAKE_CRANE_OUTPUT": "Error: GET https://ghcr.io/token?scope=x: DENIED: denied\n",
            "FAKE_CRANE_STATUS": "1",
        },
    )
    assert result.returncode == 2
    assert "could not prove that" in result.stderr
