from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Final

import pytest

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
SCRIPT: Final[Path] = REPOSITORY_ROOT / "tools" / "aws" / "image-build.sh"
BASH: Final[str] = shutil.which("bash") or "/bin/bash"
PROJECT: Final[str] = "freesecdev-linux-compliance-runner"
REPOSITORY: Final[str] = (
    "910736812072.dkr.ecr.eu-west-1.amazonaws.com/linux-compliance-runner-staging"
)
COMMIT: Final[str] = "0123456789abcdef0123456789abcdef01234567"
BUILD_ID: Final[str] = f"{PROJECT}:01234567-89ab-cdef-0123-456789abcdef"
DIGEST: Final[str] = "sha256:" + "d" * 64
DOCKER_MANIFEST: Final[str] = "application/vnd.docker.distribution.manifest.v2+json"
BUILDER: Final[str] = "quay.io/buildah/stable@sha256:" + "7" * 64

FAKE_AWS: Final[str] = """
import json, os, sys
state = os.environ["FAKE_STATE"]
with open(os.path.join(state, "calls.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
command = " ".join(sys.argv[1:3])
def answer(name):
    with open(os.path.join(state, name), encoding="utf-8") as handle:
        sys.stdout.write(handle.read())
if command == "codebuild start-build":
    answer("start.txt")
elif command == "codebuild batch-get-builds":
    counter = os.path.join(state, "polls")
    count = int(open(counter).read()) if os.path.exists(counter) else 0
    open(counter, "w").write(str(count + 1))
    running = count < int(os.environ.get("FAKE_RUNNING_POLLS", "0"))
    answer("running.json" if running else "build.json")
elif command == "codebuild stop-build":
    print("STOPPED")
elif command == "ecr describe-images":
    answer("images.json")
elif command == "logs get-log-events":
    print("last log line")
else:
    sys.exit(f"unexpected aws call {sys.argv[1:]}")
"""
FAKE_DATE: Final[str] = """
import os, sys, time
state = os.environ["FAKE_STATE"]
if sys.argv[1:] == ["+%s"]:
    path = os.path.join(state, "clock")
    now = int(open(path).read()) if os.path.exists(path) else 1_800_000_000
    open(path, "w").write(str(now + int(os.environ.get("FAKE_CLOCK_STEP", "1"))))
    print(now)
else:
    print(time.strftime("%H:%M:%SZ", time.gmtime()))
"""


def build_description(**changes: Any) -> dict[str, Any]:
    build: dict[str, Any] = {
        "id": BUILD_ID,
        "buildNumber": 12,
        "buildComplete": True,
        "buildStatus": "SUCCEEDED",
        "currentPhase": "COMPLETED",
        "startTime": "2026-10-26T12:00:00Z",
        "endTime": "2026-10-26T12:09:00Z",
        "environment": {"image": BUILDER},
        "logs": {"groupName": f"/aws/codebuild/{PROJECT}", "streamName": "stream-1"},
        "exportedEnvironmentVariables": [
            {"name": "IMAGE_DIGEST", "value": DIGEST},
            {"name": "IMAGE_TAG", "value": f"{COMMIT}-12"},
            {"name": "IMAGE_REFERENCE", "value": f"{REPOSITORY}@{DIGEST}"},
            {"name": "BUILDAH_VERSION", "value": "1.43.5"},
            {"name": "BUILT_COMMIT", "value": COMMIT},
        ],
    }
    build.update(changes)
    return build


def image_details(**changes: Any) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "imageDigest": DIGEST,
        "imageTags": [f"{COMMIT}-12"],
        "imageManifestMediaType": DOCKER_MANIFEST,
        "imagePushedAt": "2026-10-26T12:08:30Z",
        "imageSizeInBytes": 280_000_000,
    }
    detail.update(changes)
    return {"imageDetails": [detail]}


def write_executable(path: Path, source: str) -> None:
    path.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def fake(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_executable(bin_dir / "aws", FAKE_AWS)
    write_executable(bin_dir / "date", FAKE_DATE)
    (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (bin_dir / "sleep").chmod(0o755)
    (tmp_path / "start.txt").write_text(BUILD_ID + "\n", encoding="utf-8")
    store(tmp_path, build_description(), image_details())
    return tmp_path


def store(state: Path, build: dict[str, Any], images: dict[str, Any]) -> None:
    (state / "build.json").write_text(json.dumps({"builds": [build]}), encoding="utf-8")
    running = {**build, "buildComplete": False, "currentPhase": "BUILD"}
    (state / "running.json").write_text(json.dumps({"builds": [running]}), encoding="utf-8")
    (state / "images.json").write_text(json.dumps(images), encoding="utf-8")


def run(
    state: Path, *extra: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    arguments = [
        "--project",
        PROJECT,
        "--repository-uri",
        REPOSITORY,
        "--commit",
        COMMIT,
        "--build-date",
        "2026-10-26T11:00:00Z",
        "--output",
        str(state / "out" / "build.json"),
        "--timeout-minutes",
        "5",
        "--poll-seconds",
        "5",
        *extra,
    ]
    env = {
        "PATH": f"{state / 'bin'}{os.pathsep}{os.environ['PATH']}",
        "FAKE_STATE": str(state),
        **(environment or {}),
    }
    return subprocess.run(
        [BASH, str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=60,
    )


def calls(state: Path) -> list[list[str]]:
    path = state / "calls.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_successful_build_records_the_verified_digest(fake: Path) -> None:
    result = run(fake, environment={"FAKE_RUNNING_POLLS": "2"})
    assert result.returncode == 0, result.stderr
    record = json.loads((fake / "out" / "build.json").read_text(encoding="utf-8"))
    assert record == {
        "commit": COMMIT,
        "codebuild": {
            "build_id": BUILD_ID,
            "build_number": 12,
            "builder_image": BUILDER,
            "buildah_version": "1.43.5",
            "started": "2026-10-26T12:00:00Z",
            "ended": "2026-10-26T12:09:00Z",
        },
        "staging": {
            "repository": REPOSITORY,
            "tag": f"{COMMIT}-12",
            "digest": DIGEST,
            "reference": f"{REPOSITORY}@{DIGEST}",
            "pushed": "2026-10-26T12:08:30Z",
            "size_bytes": 280_000_000,
        },
    }
    made = calls(fake)
    assert made[0] == [
        "codebuild",
        "start-build",
        "--project-name",
        PROJECT,
        "--environment-variables-override",
        f"name=EXPECTED_COMMIT,value={COMMIT},type=PLAINTEXT",
        "name=BUILD_DATE,value=2026-10-26T11:00:00Z,type=PLAINTEXT",
        "--query",
        "build.id",
        "--output",
        "text",
    ]
    assert [call[:2] for call in made].count(["codebuild", "batch-get-builds"]) == 3
    assert made[-1][:2] == ["ecr", "describe-images"]
    assert f"imageDigest={DIGEST}" in made[-1]
    assert "linux-compliance-runner-staging" in made[-1]
    assert ["codebuild", "stop-build"] not in [call[:2] for call in made]
    assert "phase BUILD" in result.stdout
    assert f"staged image {REPOSITORY}@{DIGEST}" in result.stdout


@pytest.mark.parametrize(
    ("build", "images", "message"),
    [
        (
            build_description(buildStatus="FAILED"),
            image_details(),
            f"build {BUILD_ID} finished with status FAILED",
        ),
        (
            build_description(
                exportedEnvironmentVariables=[
                    *build_description()["exportedEnvironmentVariables"][:4],
                    {"name": "BUILT_COMMIT", "value": "f" * 40},
                ]
            ),
            image_details(),
            f"CodeBuild built {'f' * 40}, expected {COMMIT}",
        ),
        (
            build_description(
                exportedEnvironmentVariables=[
                    {"name": "IMAGE_DIGEST", "value": "sha256:short"},
                    {"name": "IMAGE_TAG", "value": f"{COMMIT}-12"},
                    {"name": "IMAGE_REFERENCE", "value": f"{REPOSITORY}@sha256:short"},
                    {"name": "BUILDAH_VERSION", "value": "1.43.5"},
                    {"name": "BUILT_COMMIT", "value": COMMIT},
                ]
            ),
            image_details(),
            "the build exported an invalid digest: sha256:short",
        ),
        (
            build_description(
                exportedEnvironmentVariables=[
                    {"name": "IMAGE_DIGEST", "value": DIGEST},
                    {"name": "IMAGE_TAG", "value": f"{COMMIT}-12"},
                    {"name": "IMAGE_REFERENCE", "value": f"{REPOSITORY}:latest"},
                    {"name": "BUILDAH_VERSION", "value": "1.43.5"},
                    {"name": "BUILT_COMMIT", "value": COMMIT},
                ]
            ),
            image_details(),
            f"the build exported reference {REPOSITORY}:latest",
        ),
        (
            build_description(
                exportedEnvironmentVariables=[
                    {"name": "IMAGE_DIGEST", "value": DIGEST},
                    {"name": "IMAGE_TAG", "value": "latest"},
                    {"name": "IMAGE_REFERENCE", "value": f"{REPOSITORY}@{DIGEST}"},
                    {"name": "BUILDAH_VERSION", "value": "1.43.5"},
                    {"name": "BUILT_COMMIT", "value": COMMIT},
                ]
            ),
            image_details(),
            f"the build exported tag latest, expected {COMMIT}-12",
        ),
        (
            build_description(exportedEnvironmentVariables=[]),
            image_details(),
            "the build did not export BUILT_COMMIT exactly once",
        ),
        (
            build_description(
                exportedEnvironmentVariables=[{"name": "BUILT_COMMIT", "value": COMMIT}]
            ),
            image_details(),
            "the build did not export IMAGE_DIGEST exactly once",
        ),
        (
            build_description(),
            image_details(imageDigest="sha256:" + "e" * 64),
            f"ECR does not hold {DIGEST}",
        ),
        (
            build_description(),
            image_details(imageTags=["latest"]),
            f"ECR does not hold {DIGEST}",
        ),
        (
            build_description(),
            image_details(imageManifestMediaType="application/vnd.oci.image.index.v1+json"),
            f"ECR does not hold {DIGEST}",
        ),
        (
            build_description(),
            {"imageDetails": []},
            f"ECR does not hold {DIGEST}",
        ),
    ],
)
def test_unverifiable_build_fails_without_a_record(
    fake: Path, build: dict[str, Any], images: dict[str, Any], message: str
) -> None:
    store(fake, build, images)
    result = run(fake)
    assert result.returncode == 1
    assert message in result.stderr
    assert not (fake / "out" / "build.json").exists()


def test_failed_build_prints_the_log_tail(fake: Path) -> None:
    store(fake, build_description(buildStatus="FAILED"), image_details())
    result = run(fake)
    assert "last log line" in result.stderr
    assert ["logs", "get-log-events"] in [call[:2] for call in calls(fake)]


def test_timeout_stops_the_build(fake: Path) -> None:
    result = run(fake, environment={"FAKE_RUNNING_POLLS": "1000", "FAKE_CLOCK_STEP": "120"})
    assert result.returncode == 1
    assert f"build {BUILD_ID} did not finish within 5 minutes" in result.stderr
    assert calls(fake)[-1][:4] == ["codebuild", "stop-build", "--id", BUILD_ID]


def test_unexpected_build_id_fails(fake: Path) -> None:
    (fake / "start.txt").write_text("other:project\n", encoding="utf-8")
    result = run(fake)
    assert result.returncode == 1
    assert "CodeBuild returned an unexpected build ID: other:project" in result.stderr


def test_build_reported_under_another_id_fails(fake: Path) -> None:
    store(fake, build_description(id=f"{PROJECT}:ffffffff-89ab-cdef-0123-456789abcdef"), {})
    result = run(fake)
    assert result.returncode == 1
    assert f"CodeBuild does not report build {BUILD_ID}" in result.stderr
    assert calls(fake)[-1][:4] == ["codebuild", "stop-build", "--id", BUILD_ID]


@pytest.mark.parametrize(
    ("flag", "value", "message"),
    [
        ("--project", "bad name", "--project must be a CodeBuild project name"),
        ("--repository-uri", "ghcr.io/freesecdev/x", "--repository-uri must be an ECR"),
        ("--commit", "main", "--commit must be a full commit SHA"),
        ("--build-date", "2026-10-26", "--build-date must be a UTC RFC 3339 time"),
        ("--output", "", "--output is required"),
        ("--timeout-minutes", "500", "--timeout-minutes must be between 5 and 120"),
        ("--poll-seconds", "1", "--poll-seconds must be between 5 and 120"),
    ],
)
def test_invalid_arguments_fail_before_any_aws_call(
    fake: Path, flag: str, value: str, message: str
) -> None:
    result = run(fake, flag, value)
    assert result.returncode == 1
    assert message in result.stderr
    assert calls(fake) == []


@pytest.mark.parametrize("extra", [("--unknown", "x"), ("--project",)])
def test_usage_errors_exit_2(fake: Path, extra: tuple[str, ...]) -> None:
    result = run(fake, *extra)
    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert calls(fake) == []
