from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Final, cast

import yaml

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
WORKFLOW: Final[Path] = REPOSITORY_ROOT / ".github" / "workflows" / "image-build.yml"
ZIZMOR: Final[Path] = REPOSITORY_ROOT / ".github" / "zizmor.yml"
PINNED_ACTION: Final[re.Pattern[str]] = re.compile(r"[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}")
AWS_TEXT: Final[re.Pattern[str]] = re.compile(
    r"aws-actions/|\bAWS_|vars\.AWS|\baws\s|amazonaws\.com|codebuild|\becr\b", re.IGNORECASE
)
TAG_REFERENCE: Final[re.Pattern[str]] = re.compile(r"linux-compliance-runner:")
JOB_CREDENTIAL: Final[str] = "${{ github.token }}"
DIGEST_OUTPUT: Final[str] = "${{ needs.push.outputs.reference }}"
ARCHIVE_ENVIRONMENT: Final[dict[str, str]] = {
    "EXPECTED_COMMIT": "${{ github.sha }}",
    "EXPECTED_ARCHIVE_SHA256": "${{ needs.build.outputs.archive-sha256 }}",
    "EXPECTED_CONFIG_DIGEST": "${{ needs.build.outputs.config-digest }}",
}
EXPECTED_PERMISSIONS: Final[dict[str, dict[str, str]]] = {
    "build": {"contents": "read"},
    "push": {"contents": "read", "packages": "write"},
    "smoke": {"contents": "read"},
    "scan": {"contents": "read", "packages": "read"},
    "publish": {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    },
}
EXPECTED_NEEDS: Final[dict[str, object]] = {
    "push": "build",
    "smoke": "build",
    "scan": "push",
    "publish": ["push", "smoke", "scan"],
}
ZIZMOR_FLAGGED: Final[dict[str, str]] = {
    "push": "packages: write",
    "scan": "packages: read",
    "publish": "id-token: write",
}
MAKE_STEPS: Final[dict[str, list[str]]] = {
    "build": ["make image-build"],
    "push": ["make image-archive-check", "make image-push"],
    "smoke": ["make image-smoke-archive"],
    "scan": ["make image-pull", "make image-scan", "make sbom"],
    "publish": [
        "make sbom-check",
        "make release-tag-absent",
        "make sign",
        "make verify-release",
        "make image-release",
    ],
}
TOKEN_STEPS: Final[dict[str, list[str]]] = {
    "build": [],
    "push": ["Log in to GHCR"],
    "smoke": [],
    "scan": ["Log in to GHCR to read"],
    "publish": ["Log in to GHCR", "Verify the signature and both attestations of the digest"],
}


def workflow() -> dict[Any, Any]:
    return cast("dict[Any, Any]", yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")))


def jobs() -> dict[str, dict[str, Any]]:
    return cast("dict[str, dict[str, Any]]", workflow()["jobs"])


def steps(job: str) -> list[dict[str, Any]]:
    return cast("list[dict[str, Any]]", jobs()[job]["steps"])


def named(job: str) -> dict[str, dict[str, Any]]:
    return {step["name"]: step for step in steps(job)}


def test_workflow_runs_only_on_main_and_never_for_pull_requests() -> None:
    document = workflow()
    triggers = cast("dict[str, Any]", document[True])
    assert set(triggers) == {"workflow_dispatch", "push"}
    assert triggers["push"]["branches"] == ["main"]
    assert "tools/image/**" in triggers["push"]["paths"]
    assert document["permissions"] == {}
    assert document["concurrency"] == {"group": "image-build", "cancel-in-progress": False}


def test_jobs_use_the_release_environment_and_minimal_permissions() -> None:
    found = jobs()
    assert list(found) == list(EXPECTED_PERMISSIONS)
    for name, job in found.items():
        assert job["environment"] == "release", name
        assert job["if"] == "github.ref == 'refs/heads/main'", name
        assert job["runs-on"] == "ubuntu-24.04", name
        assert job["permissions"] == EXPECTED_PERMISSIONS[name], name
        assert 0 < job["timeout-minutes"] <= 45, name
        assert job.get("needs") == EXPECTED_NEEDS.get(name), name


def test_the_build_and_the_smoke_tests_hold_no_package_or_oidc_token() -> None:
    for name in ("build", "smoke"):
        assert jobs()[name]["permissions"] == {"contents": "read"}, name
        for step in steps(name):
            assert JOB_CREDENTIAL not in str(step), step["name"]
            assert "docker login" not in str(step.get("run", "")), step["name"]
    oidc = [job for job, value in EXPECTED_PERMISSIONS.items() if "id-token" in value]
    assert oidc == ["publish"]


def test_every_action_is_pinned_by_commit_and_no_step_may_fail_silently() -> None:
    uses: list[str] = []
    for name in jobs():
        for step in steps(name):
            assert "continue-on-error" not in step, step
            if "uses" in step:
                assert PINNED_ACTION.fullmatch(step["uses"]), step["uses"]
                uses.append(step["uses"].split("@")[0])
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False
    assert "actions/attest-build-provenance" in uses
    assert "actions/attest" in uses
    assert "actions/attest-sbom" not in uses


def test_the_workflow_has_no_aws_step_credential_or_variable() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert AWS_TEXT.search(text) is None
    for name in jobs():
        for step in steps(name):
            assert not step.get("uses", "").startswith("aws-actions/"), step["name"]
            assert not any(key.startswith("AWS_") for key in step.get("env", {})), step["name"]


def test_only_registry_and_verification_steps_receive_the_job_token() -> None:
    for name in jobs():
        holders = [
            step["name"]
            for step in steps(name)
            if JOB_CREDENTIAL in cast("dict[str, str]", step.get("env", {})).values()
        ]
        assert holders == TOKEN_STEPS[name], name
        for step in steps(name):
            assert "secrets." not in str(step), step["name"]
            if "with" in step:
                assert "github-token" not in step["with"], step["name"]


def test_the_token_reaches_docker_only_on_stdin_and_is_removed_at_the_end() -> None:
    for name in jobs():
        for step in steps(name):
            if step["name"].startswith("Log in to GHCR"):
                assert step["run"] == (
                    "printf '%s' \"$GH_TOKEN\" | docker login ghcr.io "
                    '--username "$GITHUB_ACTOR" --password-stdin'
                )
        if TOKEN_STEPS[name]:
            last = steps(name)[-1]
            assert last["if"] == "${{ always() }}"
            assert last["run"] == "docker logout ghcr.io"


def test_the_make_targets_run_in_order_in_their_jobs() -> None:
    for name, expected in MAKE_STEPS.items():
        commands = [
            step["run"] for step in steps(name) if str(step.get("run", "")).startswith("make ")
        ]
        assert commands == expected, name


def test_the_build_is_bound_to_the_checked_out_commit_and_its_archive() -> None:
    build = named("build")
    record = build["Record the archive and require the built commit to be this commit"]
    for step_name in (
        "Build the checked-out commit with rootless Buildah and export it as an archive",
        "Record the archive and require the built commit to be this commit",
    ):
        assert build[step_name]["env"] == {"EXPECTED_COMMIT": "${{ github.sha }}"}, step_name
    assert '[ "$(jq -er \'.built_commit\' "$record")" = "$EXPECTED_COMMIT" ]' in record["run"]
    assert "sha256sum --check --strict -" in record["run"]
    assert set(jobs()["build"]["outputs"]) == {"config-digest", "archive-sha256"}
    upload = build["Upload the image archive and the build record"]["with"]
    assert upload["name"] == "image-archive"
    assert "GITHUB_ENV" not in WORKFLOW.read_text(encoding="utf-8")


def test_the_push_and_the_smoke_tests_verify_the_archive_recorded_by_the_build() -> None:
    push = named("push")
    step = push[
        "Push the verified archive to GHCR as a candidate and check the pushed digest, "
        "config and label"
    ]
    assert step["env"] == ARCHIVE_ENVIRONMENT
    smoke = named("smoke")
    test = smoke[
        "Run the smoke tests against the verified archive in a job without a package token"
    ]
    assert test["env"] == ARCHIVE_ENVIRONMENT
    for job in ("push", "smoke"):
        download = named(job)["Download the image archive"]["with"]
        assert download == {"name": "image-archive", "path": "build/image-build/"}
    check = push["Check the archive against the build record before any registry login"]
    assert check["env"] == ARCHIVE_ENVIRONMENT
    names = [entry["name"] for entry in steps("push")]
    assert names.index("Download the image archive") < names.index(
        "Check the archive against the build record before any registry login"
    )
    assert names.index(
        "Check the archive against the build record before any registry login"
    ) < names.index("Log in to GHCR")
    record = push["Record the pushed digest"]["run"]
    assert '[ "$reference" = "$name@$digest" ]' in record
    assert set(jobs()["push"]["outputs"]) == {"reference", "digest", "name", "release-tag"}


def test_every_registry_step_uses_the_digest_reference_not_a_tag() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert TAG_REFERENCE.search(text) is None
    for name in ("scan", "publish"):
        for step in steps(name):
            environment = cast("dict[str, str]", step.get("env", {}))
            if "IMAGE_REF" in environment:
                assert environment["IMAGE_REF"] == DIGEST_OUTPUT, step["name"]
    publish = named("publish")
    for step_name in ("Attest the build provenance of the digest", "Attest the SBOM of the digest"):
        settings = publish[step_name]["with"]
        assert settings["subject-name"] == "${{ needs.push.outputs.name }}"
        assert settings["subject-digest"] == "${{ needs.push.outputs.digest }}"
        assert settings["push-to-registry"] is True
        assert settings["create-storage-record"] is False
    assert publish["Attest the SBOM of the digest"]["with"]["sbom-path"] == (
        "build/sbom/sbom.spdx.json"
    )
    for step_name in (
        "Refuse to sign anything if the release tag already exists",
        "Tag the verified digest as the release",
    ):
        assert publish[step_name]["env"]["RELEASE_TAG"] == "${{ needs.push.outputs.release-tag }}"


def test_the_sboms_come_from_the_read_only_job_and_are_rechecked_before_attesting() -> None:
    scan = named("scan")
    assert scan["Generate the SBOMs of the candidate digest with a read-only token"]["env"] == {
        "IMAGE_REF": DIGEST_OUTPUT
    }
    names = [step["name"] for step in steps("publish")]
    assert names.index("Check that the SBOMs describe the candidate digest") < names.index(
        "Attest the SBOM of the digest"
    )
    assert "make sbom" not in [step.get("run") for step in steps("publish")]


def test_publication_is_verified_before_the_release_tag_is_set() -> None:
    names = [step["name"] for step in steps("publish")]
    order = [
        "Check that the SBOMs describe the candidate digest",
        "Refuse to sign anything if the release tag already exists",
        "Sign the candidate digest with cosign keyless",
        "Attest the build provenance of the digest",
        "Attest the SBOM of the digest",
        "Verify the signature and both attestations of the digest",
        "Tag the verified digest as the release",
    ]
    assert [name for name in names if name in order] == order
    verify = named("publish")["Verify the signature and both attestations of the digest"]
    assert verify["env"]["EXPECTED_COMMIT"] == "${{ github.sha }}"


def test_zizmor_ignores_only_the_first_sensitive_permission_of_each_job() -> None:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    rules = cast("dict[str, Any]", yaml.safe_load(ZIZMOR.read_text(encoding="utf-8")))["rules"]
    assert set(rules) == {"undocumented-permissions"}
    ignored = cast("list[str]", rules["undocumented-permissions"]["ignore"])
    expected: list[str] = []
    for job, permission in ZIZMOR_FLAGGED.items():
        start = lines.index(f"  {job}:")
        offset = next(
            index for index, line in enumerate(lines[start:]) if line.strip() == permission
        )
        expected.append(f"image-build.yml:{start + offset + 1}")
    assert ignored == expected
