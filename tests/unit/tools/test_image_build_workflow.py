from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Final, cast

import yaml

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
WORKFLOW: Final[Path] = REPOSITORY_ROOT / ".github" / "workflows" / "image-build.yml"
ZIZMOR: Final[Path] = REPOSITORY_ROOT / ".github" / "zizmor.yml"
BUILD_SCRIPT: Final[Path] = REPOSITORY_ROOT / "codebuild" / "build-image.sh"
PINNED_ACTION: Final[re.Pattern[str]] = re.compile(r"[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}")
CONFIGURE_AWS: Final[str] = "aws-actions/configure-aws-credentials@"
AWS_KEYS: Final[frozenset[str]] = frozenset(
    {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}
)
EXPECTED_PERMISSIONS: Final[dict[str, dict[str, str]]] = {
    "build": {"contents": "read", "id-token": "write"},
    "publish": {
        "contents": "read",
        "id-token": "write",
        "packages": "write",
        "attestations": "write",
    },
}
STEPS_WITH_AWS_KEYS: Final[dict[str, list[tuple[str, str]]]] = {
    "build": [
        ("Build the image in AWS CodeBuild and verify the staged digest", "aws-build"),
        ("Log in to the ECR staging registry to pull", "aws-pull"),
        ("Log in to the ECR staging registry to scan", "aws-pull"),
    ],
    "publish": [("Log in to the ECR staging registry", "aws-pull")],
}


def workflow() -> dict[Any, Any]:
    return cast("dict[Any, Any]", yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")))


def jobs() -> dict[str, dict[str, Any]]:
    return cast("dict[str, dict[str, Any]]", workflow()["jobs"])


def test_workflow_runs_only_on_main_and_never_for_pull_requests() -> None:
    document = workflow()
    triggers = cast("dict[str, Any]", document[True])
    assert set(triggers) == {"workflow_dispatch", "push"}
    assert triggers["push"]["branches"] == ["main"]
    assert document["permissions"] == {}
    assert document["concurrency"] == {"group": "image-build", "cancel-in-progress": False}


def test_jobs_use_the_release_environment_and_minimal_permissions() -> None:
    found = jobs()
    assert set(found) == set(EXPECTED_PERMISSIONS)
    for name, job in found.items():
        assert job["environment"] == "release", name
        assert job["if"] == "github.ref == 'refs/heads/main'", name
        assert job["permissions"] == EXPECTED_PERMISSIONS[name], name
        assert 0 < job["timeout-minutes"] <= 100, name
    assert found["publish"]["needs"] == "build"


def test_every_action_is_pinned_by_commit_and_no_step_may_fail_silently() -> None:
    for job in jobs().values():
        for step in cast("list[dict[str, Any]]", job["steps"]):
            assert "continue-on-error" not in step, step
            if "uses" in step:
                assert PINNED_ACTION.fullmatch(step["uses"]), step["uses"]
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_aws_credentials_are_never_exported_to_the_job() -> None:
    for job in jobs().values():
        for step in cast("list[dict[str, Any]]", job["steps"]):
            if step.get("uses", "").startswith(CONFIGURE_AWS):
                settings = step["with"]
                assert settings["output-env-credentials"] is False
                assert settings["output-credentials"] is True
                assert settings["role-duration-seconds"] <= 3600


def test_only_the_aws_steps_receive_aws_keys() -> None:
    for name, job in jobs().items():
        holders: list[tuple[str, str]] = []
        for step in cast("list[dict[str, Any]]", job["steps"]):
            environment = cast("dict[str, str]", step.get("env", {}))
            keys = AWS_KEYS & set(environment)
            if not keys:
                continue
            assert keys == AWS_KEYS, step["name"]
            sources = {
                re.fullmatch(r"\$\{\{ steps\.([a-z-]+)\.outputs\.[a-z-]+ \}\}", environment[key])
                for key in keys
            }
            assert None not in sources, step["name"]
            step_ids = {match.group(1) for match in sources if match is not None}
            assert len(step_ids) == 1, step["name"]
            holders.append((step["name"], step_ids.pop()))
            assert step["run"].startswith("make image-build") or step["run"] == (
                "make staging-login"
            )
        assert holders == STEPS_WITH_AWS_KEYS[name], name


def test_smoke_tests_run_after_a_logout_and_without_credentials() -> None:
    steps = cast("list[dict[str, Any]]", jobs()["build"]["steps"])
    names = [step["name"] for step in steps]
    smoke = names.index("Run the smoke tests against the staged digest without any credential")
    assert steps[smoke - 1]["run"] == "make staging-logout"
    assert steps[smoke]["env"] == {"IMAGE_REF": "${{ steps.record.outputs.staged }}"}
    assert steps[smoke + 1]["name"] == "Log in to the ECR staging registry to scan"


def test_scan_sbom_and_signing_use_the_digest_outputs_not_tags() -> None:
    found = jobs()
    build_steps = {step["name"]: step for step in found["build"]["steps"]}
    for name in (
        "Pull the staged digest and check its revision label",
        "Scan exactly the staged digest with the pinned Grype and apply the exception gate",
        "Generate the SBOM of the staged digest",
    ):
        assert build_steps[name]["env"] == {"IMAGE_REF": "${{ steps.record.outputs.staged }}"}
    publish_steps = {step["name"]: step for step in found["publish"]["steps"]}
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


def test_build_script_uses_the_gated_checkout_only() -> None:
    script = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert "IMAGE_SOURCE_DIR" in script
    assert 'git -C "${IMAGE_SOURCE_DIR}" rev-parse HEAD' in script
    assert "CODEBUILD_SRC_DIR" not in script
    assert "CODEBUILD_RESOLVED_SOURCE_VERSION" not in script
    assert not (REPOSITORY_ROOT / "codebuild" / "buildspec.yml").exists()
