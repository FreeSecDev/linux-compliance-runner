from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import pytest
import yaml

from tools.security import grype_gate as gate

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
EXPECTED_CONFIG_FILE: Final[Path] = REPOSITORY_ROOT / "security" / "grype-expected-config.json"
EXPECTED_CONFIG: Final[dict[str, Any]] = json.loads(
    EXPECTED_CONFIG_FILE.read_text(encoding="utf-8")
)
NOW: Final[datetime] = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
IMAGE_ID: Final[str] = "sha256:" + "a" * 64
SETTINGS: Final[gate.GateSettings] = gate.GateSettings(
    grype_version="0.121.0",
    db_schema=6,
    max_db_age=timedelta(hours=120),
    image_id=IMAGE_ID,
    distro=("alpine", "3.24.3"),
    expected_configuration=EXPECTED_CONFIG,
)


def effective_configuration() -> dict[str, Any]:
    configuration = deepcopy(EXPECTED_CONFIG)
    configuration["file"] = "build/image-scan/grype.json"
    configuration["db"]["cache-dir"] = "/work/build/grype-db/cache"
    return configuration


def grype_report() -> dict[str, Any]:
    return {
        "matches": [],
        "source": {
            "type": "image",
            "target": {
                "userInput": "localhost/linux-compliance-runner:smoke",
                "imageID": IMAGE_ID,
                "manifestDigest": "sha256:" + "b" * 64,
                "repoDigests": [],
            },
        },
        "distro": {"name": "alpine", "version": "3.24.3"},
        "descriptor": {
            "name": "grype",
            "version": "0.121.0",
            "configuration": effective_configuration(),
            "db": {
                "status": {
                    "schemaVersion": "v6.1.10",
                    "built": "2026-10-25T06:27:34Z",
                    "valid": True,
                }
            },
        },
    }


def write_inputs(tmp_path: Path, report: object) -> tuple[Path, Path]:
    report_path = tmp_path / "grype.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    exceptions_path = tmp_path / "exceptions.yaml"
    exceptions_path.write_text(
        "---\n" + yaml.safe_dump({"format": 2, "exceptions": []}, sort_keys=False),
        encoding="utf-8",
    )
    return report_path, exceptions_path


def cli_arguments(report: Path, exceptions: Path, *extra: str) -> list[str]:
    return [
        "--report",
        str(report),
        "--exceptions",
        str(exceptions),
        "--grype-version",
        "0.121.0",
        "--db-schema",
        "6",
        "--max-db-age-hours",
        "120",
        "--image-id",
        IMAGE_ID,
        "--distro",
        "alpine",
        "--distro-version",
        "3.24.3",
        "--expected-config",
        str(EXPECTED_CONFIG_FILE),
        *extra,
    ]


PUSHED: Final[str] = "ghcr.io/freesecdev/linux-compliance-runner"
BUILT_DIGEST: Final[str] = "sha256:" + "d" * 64
BUILT_REFERENCE: Final[str] = f"{PUSHED}@{BUILT_DIGEST}"
DOCKER_MANIFEST: Final[str] = "application/vnd.docker.distribution.manifest.v2+json"
OCI_MANIFEST: Final[str] = "application/vnd.oci.image.manifest.v1+json"
REFERENCE_SETTINGS: Final[gate.GateSettings] = gate.GateSettings(
    grype_version="0.121.0",
    db_schema=6,
    max_db_age=timedelta(hours=120),
    image_id=BUILT_DIGEST,
    distro=("alpine", "3.24.3"),
    expected_configuration=EXPECTED_CONFIG,
    image_reference=BUILT_REFERENCE,
)


def registry_report(**target: object) -> dict[str, Any]:
    document = grype_report()
    document["source"]["target"] = {
        "userInput": BUILT_REFERENCE,
        "imageID": IMAGE_ID,
        "manifestDigest": BUILT_DIGEST,
        "mediaType": DOCKER_MANIFEST,
        "repoDigests": [BUILT_REFERENCE],
        **target,
    }
    return document


def reference_settings(image_id: str, reference: str) -> gate.GateSettings:
    return gate.GateSettings(
        grype_version="0.121.0",
        db_schema=6,
        max_db_age=timedelta(hours=120),
        image_id=image_id,
        distro=("alpine", "3.24.3"),
        expected_configuration=EXPECTED_CONFIG,
        image_reference=reference,
    )


def decide_reference(
    document: dict[str, Any], settings: gate.GateSettings = REFERENCE_SETTINGS
) -> tuple[str, ...]:
    return gate.evaluate(gate.parse_report(document), (), settings, NOW).failures


def test_registry_scan_of_the_built_digest_passes() -> None:
    assert decide_reference(registry_report()) == ()


def test_without_a_reference_the_gate_does_not_require_a_registry_scan() -> None:
    assert gate.reference_failures(gate.parse_report(grype_report()), SETTINGS) == []


@pytest.mark.parametrize(
    "reference",
    [
        f"{PUSHED}:latest",
        f"{PUSHED}:{'a' * 40}-1",
        PUSHED,
        f"{PUSHED}@sha256:{'d' * 63}",
        f"{PUSHED}@sha512:{'d' * 128}",
        f"{PUSHED}:tag@{BUILT_DIGEST}",
        f"registry:{BUILT_REFERENCE}",
        f"{BUILT_REFERENCE}\n",
        f"UPPER/{BUILT_REFERENCE}",
    ],
)
def test_reference_must_be_a_digest_never_a_tag(reference: str) -> None:
    settings = reference_settings(BUILT_DIGEST, reference)
    failures = decide_reference(registry_report(userInput=reference), settings)
    expected = (
        f"--image-reference {reference!r} is not a name@sha256:<digest> reference; "
        "a tag is never accepted"
    )
    assert failures == (expected,)


def test_report_of_a_tag_fails_even_if_the_digest_matches() -> None:
    failures = decide_reference(registry_report(userInput=f"{PUSHED}:latest"))
    assert failures == (f"report scanned '{PUSHED}:latest', expected exactly '{BUILT_REFERENCE}'",)


def test_report_of_another_manifest_fails() -> None:
    other = "sha256:" + "e" * 64
    failures = decide_reference(registry_report(manifestDigest=other, repoDigests=[]))
    assert failures == (
        f"report scanned manifest {other}, expected the built digest {BUILT_DIGEST}",
        f"report does not describe the image {BUILT_DIGEST}",
    )


def test_index_digest_scan_fails_because_the_platform_manifest_differs() -> None:
    platform = "sha256:" + "f" * 64
    failures = decide_reference(registry_report(manifestDigest=platform))
    assert failures == (
        f"report scanned manifest {platform}, expected the built digest {BUILT_DIGEST}",
    )


def test_report_without_manifest_digest_or_media_type_fails() -> None:
    document = registry_report()
    del document["source"]["target"]["manifestDigest"]
    document["source"]["target"]["mediaType"] = None
    assert decide_reference(document) == (
        f"report scanned manifest None, expected the built digest {BUILT_DIGEST}",
        "report scanned media type None, expected a single image manifest",
    )


def test_oci_and_docker_image_manifests_are_accepted() -> None:
    assert {DOCKER_MANIFEST, OCI_MANIFEST} == gate.IMAGE_MANIFEST_TYPES
    assert decide_reference(registry_report(mediaType=OCI_MANIFEST)) == ()


@pytest.mark.parametrize(
    "media_type",
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v1+prettyjws",
    ],
)
def test_index_or_legacy_media_type_fails(media_type: str) -> None:
    assert decide_reference(registry_report(mediaType=media_type)) == (
        f"report scanned media type {media_type!r}, expected a single image manifest",
    )


def test_non_image_source_fails() -> None:
    document = registry_report()
    document["source"]["type"] = "directory"
    assert decide_reference(document) == ("report source type is 'directory', expected 'image'",)


def test_missing_source_type_is_reported_as_none() -> None:
    document = registry_report()
    del document["source"]["type"]
    assert decide_reference(document) == ("report source type is None, expected 'image'",)


def test_image_id_must_be_the_reference_digest() -> None:
    settings = reference_settings(IMAGE_ID, BUILT_REFERENCE)
    assert decide_reference(registry_report(), settings) == (
        f"--image-id {IMAGE_ID} is not the digest of {BUILT_REFERENCE}",
    )


def test_wrongly_typed_media_type_is_rejected() -> None:
    with pytest.raises(gate.ReportError, match=r"source\.target\.mediaType must be a string"):
        gate.parse_report(registry_report(mediaType=7))


def test_summary_shows_the_expected_reference_and_scanned_manifest() -> None:
    report = gate.parse_report(registry_report())
    decision = gate.evaluate(report, (), REFERENCE_SETTINGS, NOW)
    summary = gate.render_summary(decision, report, REFERENCE_SETTINGS, NOW)
    assert f"| Expected reference | {BUILT_REFERENCE} |" in summary
    assert f"| Scanned manifest | {BUILT_DIGEST} |" in summary


def test_summary_without_manifest_digest() -> None:
    document = grype_report()
    del document["source"]["target"]["manifestDigest"]
    report = gate.parse_report(document)
    summary = gate.render_summary(gate.evaluate(report, (), SETTINGS, NOW), report, SETTINGS, NOW)
    assert "| Scanned manifest | not reported |" in summary


def test_main_binds_the_scan_to_the_reference(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report, exceptions = write_inputs(tmp_path, registry_report())
    arguments = cli_arguments(report, exceptions, "--image-reference", BUILT_REFERENCE)
    arguments[arguments.index("--image-id") + 1] = BUILT_DIGEST
    assert gate.main(arguments, now=NOW) == 0
    assert "PASSED" in capsys.readouterr().out
    arguments[arguments.index("--image-reference") + 1] = f"{PUSHED}:latest"
    assert gate.main(arguments, now=NOW) == 1
    assert "a tag is never accepted" in capsys.readouterr().out
