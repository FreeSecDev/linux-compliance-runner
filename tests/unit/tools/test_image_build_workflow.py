from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Final, cast

import yaml

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
WORKFLOW: Final[Path] = REPOSITORY_ROOT / ".github" / "workflows" / "image-build.yml"
ZIZMOR: Final[Path] = REPOSITORY_ROOT / ".github" / "zizmor.yml"
BUILDSPEC: Final[Path] = REPOSITORY_ROOT / "codebuild" / "buildspec.yml"
PINNED_ACTION: Final[re.Pattern[str]] = re.compile(r"[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}")
EXPECTED_PERMISSIONS: Final[dict[str, dict[str, str]]] = {
    "build": {"contents": "read", "id-token": "write"},
    "publish": {
        "contents": "read",
        "id-token": "write",
        "packages": "write",
        "attestations": "write",
    },
}


def workflow() -> dict[Any, Any]:
    return cast("dict[Any, Any]", yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")))


def test_workflow_runs_only_on_main_and_never_for_pull_requests() -> None:
    document = workflow()
    triggers = cast("dict[str, Any]", document[True])
    assert set(triggers) == {"workflow_dispatch", "push"}
    assert triggers["push"]["branches"] == ["main"]
    assert document["permissions"] == {}
    assert document["concurrency"] == {"group": "image-build", "cancel-in-progress": False}


def test_jobs_use_the_release_environment_and_minimal_permissions() -> None:
    jobs = cast("dict[str, dict[str, Any]]", workflow()["jobs"])
    assert set(jobs) == set(EXPECTED_PERMISSIONS)
    for name, job in jobs.items():
        assert job["environment"] == "release", name
        assert job["if"] == "github.ref == 'refs/heads/main'", name
        assert job["permissions"] == EXPECTED_PERMISSIONS[name], name
        assert 0 < job["timeout-minutes"] <= 90, name
    assert jobs["publish"]["needs"] == "build"


def test_every_action_is_pinned_by_commit_and_no_step_may_fail_silently() -> None:
    for job in cast("dict[str, dict[str, Any]]", workflow()["jobs"]).values():
        for step in cast("list[dict[str, Any]]", job["steps"]):
            assert "continue-on-error" not in step, step
            if "uses" in step:
                assert PINNED_ACTION.fullmatch(step["uses"]), step["uses"]
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_scan_sbom_and_signing_use_the_digest_outputs_not_tags() -> None:
    jobs = cast("dict[str, dict[str, Any]]", workflow()["jobs"])
    build_steps = {step["name"]: step for step in jobs["build"]["steps"]}
    for name in (
        "Pull the staged digest and check its revision label",
        "Run the smoke tests against the staged digest",
        "Scan exactly the staged digest with the pinned Grype and apply the exception gate",
        "Generate the SBOM of the staged digest",
    ):
        assert build_steps[name]["env"] == {"IMAGE_REF": "${{ steps.record.outputs.staged }}"}
    publish_steps = {step["name"]: step for step in jobs["publish"]["steps"]}
    assert publish_steps["Sign the release digest with cosign keyless"]["env"] == {
        "IMAGE_REF": "${{ steps.release.outputs.reference }}"
    }
    for name in (
        "Attest the build provenance of the release digest",
        "Attest the SBOM of the release digest",
    ):
        settings = publish_steps[name]["with"]
        assert settings["subject-digest"] == "${{ steps.release.outputs.digest }}"
        assert settings["push-to-registry"] is True


def test_zizmor_ignores_only_the_id_token_lines_of_the_two_jobs() -> None:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    rules = cast("dict[str, Any]", yaml.safe_load(ZIZMOR.read_text(encoding="utf-8")))["rules"]
    assert set(rules) == {"undocumented-permissions"}
    ignored = cast("list[str]", rules["undocumented-permissions"]["ignore"])
    id_token_lines = [
        f"image-build.yml:{number}"
        for number, line in enumerate(lines, start=1)
        if line.strip() == "id-token: write"
    ]
    assert ignored == id_token_lines
    assert len(ignored) == len(EXPECTED_PERMISSIONS)


def test_buildspec_runs_the_versioned_build_script_and_exports_the_digest() -> None:
    buildspec = cast("dict[str, Any]", yaml.safe_load(BUILDSPEC.read_text(encoding="utf-8")))
    assert buildspec["version"] == 0.2
    assert buildspec["env"]["exported-variables"] == [
        "IMAGE_DIGEST",
        "IMAGE_TAG",
        "IMAGE_REFERENCE",
        "BUILDAH_VERSION",
    ]
    assert set(buildspec["phases"]) == {"build"}
    assert buildspec["phases"]["build"]["on-failure"] == "ABORT"
    assert buildspec["phases"]["build"]["commands"] == [
        "bash codebuild/build-image.sh",
        ". /tmp/image-build/result.env",
    ]
