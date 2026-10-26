from __future__ import annotations

import json
import runpy
import sys
from copy import deepcopy
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import pytest
import yaml

from tools.security import grype_gate as gate
from tools.security.vulnerability_exceptions import VulnerabilityException

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
EXPECTED_CONFIG_FILE: Final[Path] = REPOSITORY_ROOT / "security" / "grype-expected-config.json"
EXPECTED_CONFIG: Final[dict[str, Any]] = json.loads(
    EXPECTED_CONFIG_FILE.read_text(encoding="utf-8")
)
NOW: Final[datetime] = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
IMAGE_ID: Final[str] = "sha256:" + "a" * 64
MANIFEST_DIGEST: Final[str] = "sha256:" + "b" * 64
REPO_DIGEST: Final[str] = "sha256:" + "c" * 64
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


def grype_match(
    vulnerability_id: str,
    package: str = "golang.org/x/net",
    version: str = "v0.57.0",
    severity: str = "High",
) -> dict[str, Any]:
    return {
        "vulnerability": {
            "id": vulnerability_id,
            "severity": severity,
            "fix": {"state": "fixed", "versions": ["0.60.0"]},
        },
        "artifact": {
            "name": package,
            "version": version,
            "type": "go-module",
            "locations": [{"path": "/usr/local/bin/tofu", "layerID": "sha256:0"}],
        },
    }


def at_locations(match: dict[str, Any], *paths: str) -> dict[str, Any]:
    match["artifact"]["locations"] = [{"path": path} for path in paths]
    return match


def grype_report(*matches: dict[str, Any]) -> dict[str, Any]:
    return {
        "matches": list(matches),
        "source": {
            "type": "image",
            "target": {
                "userInput": "localhost/linux-compliance-runner:smoke",
                "imageID": IMAGE_ID,
                "manifestDigest": MANIFEST_DIGEST,
                "repoDigests": [f"localhost/linux-compliance-runner@{REPO_DIGEST}"],
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


def accepted(
    vulnerability_id: str,
    package: str = "golang.org/x/net",
    version: str = "v0.57.0",
    severity: str = "high",
) -> VulnerabilityException:
    return VulnerabilityException(
        vulnerability_id=vulnerability_id,
        package=package,
        version=version,
        component=f"{package} {version}",
        severity=severity,
        justification="Not exploitable in the toolbox.",
        owner="lead architect",
        jira="FREES-37",
        created=date(2026, 10, 25),
        expires=date(2027, 1, 23),
    )


def decide(
    report: dict[str, Any], *exceptions: VulnerabilityException, now: datetime = NOW
) -> gate.Decision:
    return gate.evaluate(gate.parse_report(report), exceptions, SETTINGS, now)


def exception_entry(**changes: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "id": "GO-2026-6612",
        "package": "golang.org/x/net",
        "version": "v0.57.0",
        "component": "golang.org/x/net v0.57.0 inside OpenTofu",
        "severity": "critical",
        "justification": "Client-side use only.",
        "owner": "lead architect",
        "jira": "FREES-37",
        "created": "2026-10-25",
        "expires": "2027-01-23",
    }
    entry.update(changes)
    return entry


def write_inputs(tmp_path: Path, report: object, *entries: dict[str, object]) -> tuple[Path, Path]:
    report_path = tmp_path / "grype.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    exceptions_path = tmp_path / "exceptions.yaml"
    exceptions_path.write_text(
        "---\n" + yaml.safe_dump({"format": 2, "exceptions": list(entries)}, sort_keys=False),
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


def test_clean_report_passes() -> None:
    decision = decide(grype_report())
    assert decision.passed
    assert decision.failures == ()
    assert decision.accepted == ()


def test_listed_finding_is_accepted_and_lower_severities_do_not_block() -> None:
    report = grype_report(
        grype_match("GO-2026-6612", severity="Critical"),
        grype_match("CVE-2026-1", "busybox", "1.37.0-r31", "Medium"),
        grype_match("CVE-2026-2", "python", "3.12.15", "Low"),
        grype_match("CVE-2026-3", "python", "3.12.15", "Negligible"),
    )
    entry = accepted("GO-2026-6612", severity="critical")
    decision = decide(report, entry)
    assert decision.passed
    assert [(finding.vulnerability_id, exception) for finding, exception in decision.accepted] == [
        ("GO-2026-6612", entry)
    ]


def test_listed_unknown_severity_finding_is_accepted() -> None:
    report = grype_report(grype_match("CVE-2026-9", "python", "3.12.15", "Unknown"))
    entry = accepted("CVE-2026-9", "python", "3.12.15", "unknown")
    decision = decide(report, entry)
    assert decision.passed
    assert decision.accepted[0][1] == entry


@pytest.mark.parametrize("severity", ["Critical", "High", "Unknown"])
def test_unlisted_critical_or_high_finding_fails(severity: str) -> None:
    decision = decide(grype_report(grype_match("GO-2026-6612", severity=severity)))
    assert not decision.passed
    assert decision.failures == (
        (
            f"unlisted {severity.lower()} GO-2026-6612 in golang.org/x/net v0.57.0 (go-module) at "
            "/usr/local/bin/tofu; fix: fixed (0.60.0)"
        ),
    )


def test_unlisted_finding_without_fix_or_location_is_described() -> None:
    finding = at_locations(grype_match("GHSA-x", "ecdsa", "0.19.2"))
    finding["vulnerability"]["fix"] = {"state": "not-fixed", "versions": []}
    decision = decide(grype_report(finding))
    assert decision.failures == (
        "unlisted high GHSA-x in ecdsa 0.19.2 (go-module) at <no location>; fix: not-fixed",
    )


def test_id_listed_for_a_different_package_does_not_match() -> None:
    report = grype_report(grype_match("GO-2026-6612", "golang.org/x/crypto", "v0.40.0"))
    decision = decide(report, accepted("GO-2026-6612"))
    assert not decision.passed
    assert decision.accepted == ()
    assert decision.failures == (
        (
            "unlisted high GO-2026-6612 in golang.org/x/crypto v0.40.0 (go-module) at "
            "/usr/local/bin/tofu; fix: fixed (0.60.0); GO-2026-6612 is listed only for "
            "golang.org/x/net v0.57.0"
        ),
        (
            "stale exception: GO-2026-6612 in golang.org/x/net v0.57.0 (FREES-37) is no longer "
            "reported; remove the entry"
        ),
    )


def test_id_listed_for_another_version_of_the_package_does_not_match() -> None:
    report = grype_report(grype_match("GO-2026-6612", version="v0.58.0"))
    decision = decide(report, accepted("GO-2026-6612"))
    assert not decision.passed
    assert "listed only for golang.org/x/net v0.57.0" in decision.failures[0]
    assert decision.failures[1].startswith("stale exception: GO-2026-6612")


def test_stale_entry_fails() -> None:
    decision = decide(grype_report(), accepted("GO-2026-6612"))
    assert decision.failures == (
        (
            "stale exception: GO-2026-6612 in golang.org/x/net v0.57.0 (FREES-37) is no longer "
            "reported; remove the entry"
        ),
    )


def test_stale_entry_for_a_low_severity_listing_fails() -> None:
    decision = decide(grype_report(), accepted("CVE-1", "busybox", "1.0", "low"))
    assert decision.failures[0].startswith("stale exception: CVE-1 in busybox 1.0")


def test_listed_finding_with_changed_severity_fails() -> None:
    report = grype_report(grype_match("GO-2026-6603", severity="Critical"))
    decision = decide(report, accepted("GO-2026-6603"))
    assert decision.accepted == ()
    assert decision.failures == (
        (
            "GO-2026-6603 in golang.org/x/net v0.57.0 is listed as high but reported as critical; "
            "re-assess the exception"
        ),
    )


def test_one_entry_covers_the_same_package_in_several_artifacts() -> None:
    report = grype_report(
        at_locations(grype_match("GO-2026-6603"), "/usr/local/bin/tofu"),
        at_locations(grype_match("GO-2026-6603"), "/usr/local/bin/other"),
    )
    decision = decide(report, accepted("GO-2026-6603"))
    assert decision.passed
    assert len(decision.accepted) == 2


def test_accepted_findings_are_sorted_by_severity_then_key() -> None:
    report = grype_report(
        grype_match("GO-2", severity="High"),
        grype_match("GO-1", severity="High"),
        grype_match("GO-3", severity="Critical"),
    )
    decision = decide(
        report, accepted("GO-2"), accepted("GO-1"), accepted("GO-3", severity="critical")
    )
    assert [finding.vulnerability_id for finding, _ in decision.accepted] == [
        "GO-3",
        "GO-1",
        "GO-2",
    ]


def test_stale_database_fails() -> None:
    decision = decide(grype_report(), now=datetime(2026, 10, 30, 6, 27, 35, tzinfo=UTC))
    assert decision.failures == (
        (
            "vulnerability database built 2026-10-25T06:27:34Z is 120.0 hours old, more than the "
            "120-hour limit; a stale database can hide new findings"
        ),
    )


def test_database_at_the_age_limit_passes() -> None:
    assert decide(grype_report(), now=datetime(2026, 10, 30, 6, 27, 34, tzinfo=UTC)).passed


def test_database_built_in_the_future_fails() -> None:
    decision = decide(grype_report(), now=datetime(2026, 10, 25, 6, 0, tzinfo=UTC))
    assert decision.failures == (
        "vulnerability database build time 2026-10-25T06:27:34Z is in the future",
    )


def test_database_within_clock_skew_passes() -> None:
    assert decide(grype_report(), now=datetime(2026, 10, 25, 6, 23, tzinfo=UTC)).passed


def test_invalid_database_fails() -> None:
    report = grype_report()
    report["descriptor"]["db"]["status"]["valid"] = False
    assert decide(report).failures == ("Grype reports the vulnerability database as invalid",)


@pytest.mark.parametrize("schema", ["v5.1.0", "v6", "v61.0.0", "6.1.10", "v6.1.10-rc"])
def test_wrong_database_schema_fails(schema: str) -> None:
    report = grype_report()
    report["descriptor"]["db"]["status"]["schemaVersion"] = schema
    assert decide(report).failures == (f"vulnerability database schema {schema!r} is not v6",)


def test_other_grype_version_fails() -> None:
    report = grype_report()
    report["descriptor"]["version"] = "0.120.1"
    assert decide(report).failures == (
        "report was produced by Grype 0.120.1, expected the pinned 0.121.0",
    )


def test_report_of_another_image_fails() -> None:
    report = grype_report()
    report["source"]["target"]["imageID"] = "sha256:" + "d" * 64
    report["source"]["target"]["manifestDigest"] = "sha256:" + "e" * 64
    report["source"]["target"]["repoDigests"] = []
    assert decide(report).failures == (f"report does not describe the image {IMAGE_ID}",)


@pytest.mark.parametrize("expected", [MANIFEST_DIGEST, REPO_DIGEST])
def test_image_matches_by_manifest_or_repository_digest(expected: str) -> None:
    report = gate.parse_report(grype_report())
    settings = gate.GateSettings(
        "0.121.0", 6, timedelta(hours=120), expected, ("alpine", "3.24.3"), EXPECTED_CONFIG
    )
    assert gate.evaluate(report, (), settings, NOW).passed


def test_image_digests_ignore_malformed_values() -> None:
    report = grype_report()
    report["source"]["target"]["manifestDigest"] = None
    del report["source"]["target"]["repoDigests"]
    assert gate.parse_report(report).image_digests == frozenset({IMAGE_ID})
    report["source"]["target"]["repoDigests"] = ["localhost/x@sha256:short"]
    assert gate.parse_report(report).image_digests == frozenset({IMAGE_ID})


@pytest.mark.parametrize(
    ("name", "version", "shown"),
    [
        ("", "3.24.3", "' 3.24.3'"),
        ("alpine", "3.10.9", "'alpine 3.10.9'"),
        ("alpine", "", "'alpine '"),
    ],
)
def test_other_distribution_or_release_fails(name: str, version: str, shown: str) -> None:
    report = grype_report()
    report["distro"] = {"name": name, "version": version, "idLike": []}
    assert decide(report).failures == (
        f"report detected distribution {shown}, expected 'alpine 3.24.3'",
    )


CONFIG_MUTATIONS: Final[list[tuple[tuple[str, ...], object]]] = [
    (("match", "stock", "using-cpes"), False),
    (("match", "python", "using-cpes"), True),
    (("match", "golang", "always-use-cpe-for-stdlib"), True),
    (("match", "dpkg", "missing-epoch-strategy"), "auto"),
    (("platform",), "linux/arm64"),
    (("search", "scope"), "all-layers"),
    (("search", "indexed-archives"), False),
    (("search", "unindexed-archives"), True),
    (("from",), ["registry"]),
    (("default-image-pull-source",), "registry"),
    (("distro",), "alpine:3.10"),
    (("only-fixed",), True),
    (("only-fixed",), 0),
    (("only-notfixed",), True),
    (("ignore-wontfix",), "wont-fix"),
    (("exclude",), ["/opt/**"]),
    (("vex-documents",), ["vex.json"]),
    (("vex-add",), ["not_affected"]),
    (("ignore",), []),
    (("db", "validate-age"), False),
    (("db", "auto-update"), True),
    (("db", "max-allowed-built-age"), 864000000000000),
    (("db", "update-url"), "https://mirror.example.org/databases"),
    (("externalSources", "enable"), True),
    (("output",), ["json", "table"]),
]


@pytest.mark.parametrize(("path", "value"), CONFIG_MUTATIONS, ids=str)
def test_configuration_mutation_fails(path: tuple[str, ...], value: object) -> None:
    report = grype_report()
    node: Any = report["descriptor"]["configuration"]
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    failures = decide(report).failures
    differs = "Grype configuration differs from the expected configuration: "
    invariant = "Grype configuration breaks a gate invariant: "
    assert failures
    assert all(failure.startswith((differs, invariant)) for failure in failures)
    assert any(failure.startswith(differs) and ".".join(path) in failure for failure in failures)


def test_configuration_difference_message() -> None:
    report = grype_report()
    report["descriptor"]["configuration"]["match"]["stock"]["using-cpes"] = False
    assert decide(report).failures == (
        (
            "Grype configuration breaks a gate invariant: "
            "match.stock.using-cpes must be true, got false"
        ),
        (
            "Grype configuration differs from the expected configuration: "
            "match.stock.using-cpes: expected true, got false"
        ),
    )


def test_new_or_missing_setting_fails() -> None:
    report = grype_report()
    report["descriptor"]["configuration"]["brand-new-setting"] = {"enabled": True}
    del report["descriptor"]["configuration"]["timestamp"]
    assert decide(report).failures == (
        (
            "Grype configuration differs from the expected configuration: brand-new-setting is a "
            'new or unknown setting ({"enabled": true})'
        ),
        "Grype configuration differs from the expected configuration: timestamp is missing",
    )


@pytest.mark.parametrize("value", ["", None, 5])
def test_variable_field_must_be_a_non_empty_string(value: object) -> None:
    report = grype_report()
    report["descriptor"]["configuration"]["db"]["cache-dir"] = value
    assert decide(report).failures == (
        (
            "Grype configuration differs from the expected configuration: db.cache-dir must be a "
            f"non-empty string, got {json.dumps(value)}"
        ),
    )


def test_variable_fields_may_hold_any_path() -> None:
    report = grype_report()
    report["descriptor"]["configuration"]["file"] = "/elsewhere/report.json"
    report["descriptor"]["configuration"]["db"]["cache-dir"] = "/other/checkout/cache"
    assert decide(report).passed


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("search",), "squashed", 'search: expected an object, got "squashed"'),
        (("ignore",), "all", "ignore: expected"),
        (("ignore", 0, "package", "name"), "kernel", "ignore[0].package.name: expected"),
    ],
)
def test_configuration_shape_changes_fail(
    path: tuple[str | int, ...], value: object, message: str
) -> None:
    report = grype_report()
    node: Any = report["descriptor"]["configuration"]
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    assert any(message in failure for failure in decide(report).failures)


def test_configuration_differences_reports_a_non_object_root() -> None:
    assert gate.configuration_differences([], {"a": 1}) == ["<root>: expected an object, got []"]


def test_database_age_limit_comes_from_the_settings() -> None:
    report = grype_report()
    report["descriptor"]["configuration"]["db"]["max-allowed-built-age"] = 3600 * 10**9
    settings = gate.GateSettings(
        "0.121.0", 6, timedelta(hours=1), IMAGE_ID, ("alpine", "3.24.3"), EXPECTED_CONFIG
    )
    later = datetime(2026, 10, 25, 7, 0, tzinfo=UTC)
    assert gate.evaluate(gate.parse_report(report), (), settings, later).passed
    assert not decide(report).passed


def test_expected_configuration_without_db_section_is_copied() -> None:
    assert gate.expected_configuration_for({"a": 1}, timedelta(hours=1)) == {"a": 1}


def set_path(configuration: dict[str, Any], path: tuple[str, ...], value: object) -> None:
    node: Any = configuration
    for step in path[:-1]:
        node = node[step]
    if value is DELETE:
        del node[path[-1]]
    else:
        node[path[-1]] = value


DELETE: Final[object] = object()
EXTRA_IGNORE_RULE: Final[dict[str, Any]] = {
    **gate.BUILTIN_IGNORE_RULES[0],
    "vulnerability": "CVE-2026-1",
}
INVARIANT_MUTATIONS: Final[list[tuple[tuple[str, ...], object, str]]] = [
    (("only-fixed",), True, "only-fixed must be false, got true"),
    (("only-notfixed",), True, "only-notfixed must be false, got true"),
    (("ignore-wontfix",), "fixed", 'ignore-wontfix must be "", got "fixed"'),
    (("exclude",), ["./opt/python/**"], 'exclude must be [], got ["./opt/python/**"]'),
    (("vex-documents",), ["vex.json"], "vex-documents must be []"),
    (("vex-add",), ["fixed"], "vex-add must be []"),
    (("ignore",), [*gate.BUILTIN_IGNORE_RULES, EXTRA_IGNORE_RULE], "ignore must be"),
    (("ignore",), list(gate.BUILTIN_IGNORE_RULES[1:]), "ignore must be"),
    (("ignore",), [], "ignore must be"),
    (("distro",), "alpine:3.10", 'distro must be "", got "alpine:3.10"'),
    (("platform",), "linux/arm64", 'platform must be "", got "linux/arm64"'),
    (("from",), ["registry"], 'from must be null or [], got ["registry"]'),
    (("from",), "registry", 'from must be null or [], got "registry"'),
    (("from",), DELETE, "from must be null or [], got <missing>"),
    (("default-image-pull-source",), "registry", "default-image-pull-source must be"),
    (("by-cve",), True, "by-cve must be false, got true"),
    (("match", "stock", "using-cpes"), False, "match.stock.using-cpes must be true, got false"),
    (("match", "jvm", "using-cpes"), False, "match.jvm.using-cpes must be true, got false"),
    (("match", "stock"), DELETE, "match.stock.using-cpes must be true, got <missing>"),
    (("match",), "none", "match.stock.using-cpes must be true, got <missing>"),
    (("db", "auto-update"), True, "db.auto-update must be false, got true"),
    (("db", "validate-age"), False, "db.validate-age must be true, got false"),
    (("db", "validate-by-hash-on-start"), False, "db.validate-by-hash-on-start must be true"),
    (("search", "scope"), "none", 'search.scope must be one of all-layers, squashed, got "none"'),
    (("search",), DELETE, "search.scope must be one of all-layers, squashed, got <missing>"),
    (("search",), DELETE, "search.indexed-archives must be true, got <missing>"),
    (("search", "indexed-archives"), False, "search.indexed-archives must be true, got false"),
    (("search", "indexed-archives"), 1, "search.indexed-archives must be true, got 1"),
    (("search", "indexed-archives"), "true", 'search.indexed-archives must be true, got "true"'),
    (("search", "indexed-archives"), None, "search.indexed-archives must be true, got null"),
    (
        ("search", "indexed-archives"),
        DELETE,
        "search.indexed-archives must be true, got <missing>",
    ),
]


@pytest.mark.parametrize(("path", "value", "message"), INVARIANT_MUTATIONS, ids=str)
def test_invariant_holds_even_when_the_expected_file_is_weakened_to_match(
    path: tuple[str, ...], value: object, message: str
) -> None:
    report = grype_report()
    set_path(report["descriptor"]["configuration"], path, value)
    weakened = deepcopy(EXPECTED_CONFIG)
    set_path(weakened, path, value)
    settings = gate.GateSettings(
        "0.121.0", 6, timedelta(hours=120), IMAGE_ID, ("alpine", "3.24.3"), weakened
    )
    failures = gate.evaluate(gate.parse_report(report), (), settings, NOW).failures
    assert not any("differs from the expected configuration" in failure for failure in failures)
    assert any(
        failure.startswith("Grype configuration breaks a gate invariant: ") and message in failure
        for failure in failures
    )
    assert any(
        failure.startswith("expected configuration file breaks a gate invariant: ")
        and message in failure
        for failure in failures
    )


@pytest.mark.parametrize(
    ("path", "value"),
    [(("from",), []), (("from",), None), (("search", "scope"), "all-layers")],
)
def test_allowed_invariant_alternatives_pass(path: tuple[str, ...], value: object) -> None:
    report = grype_report()
    set_path(report["descriptor"]["configuration"], path, value)
    expected = deepcopy(EXPECTED_CONFIG)
    set_path(expected, path, value)
    settings = gate.GateSettings(
        "0.121.0", 6, timedelta(hours=120), IMAGE_ID, ("alpine", "3.24.3"), expected
    )
    assert gate.evaluate(gate.parse_report(report), (), settings, NOW).passed


def test_committed_expected_configuration_satisfies_every_invariant() -> None:
    assert gate.invariant_violations(EXPECTED_CONFIG) == []


def test_invariants_cover_every_cpe_matcher_enabled_in_the_baseline() -> None:
    enabled = {
        name for name, matcher in EXPECTED_CONFIG["match"].items() if matcher.get("using-cpes")
    }
    required = {path[1] for path, value in gate.INVARIANTS if path[0] == "match" and value is True}
    assert enabled == required == {"jvm", "stock"}


def test_invariants_require_indexed_archive_search() -> None:
    assert EXPECTED_CONFIG["search"]["indexed-archives"] is True
    assert (("search", "indexed-archives"), True) in gate.INVARIANTS


def test_indexed_archives_invariant_fails_although_the_weakened_report_matches_the_file() -> None:
    report = grype_report()
    report["descriptor"]["configuration"]["search"]["indexed-archives"] = False
    weakened = deepcopy(EXPECTED_CONFIG)
    weakened["search"]["indexed-archives"] = False
    settings = gate.GateSettings(
        "0.121.0", 6, timedelta(hours=120), IMAGE_ID, ("alpine", "3.24.3"), weakened
    )
    decision = gate.evaluate(gate.parse_report(report), (), settings, NOW)
    assert not decision.passed
    violation = "search.indexed-archives must be true, got false"
    assert decision.failures == (
        f"Grype configuration breaks a gate invariant: {violation}",
        f"expected configuration file breaks a gate invariant: {violation}",
    )


def test_builtin_ignore_rules_equal_the_baseline() -> None:
    assert EXPECTED_CONFIG["ignore"] == list(gate.BUILTIN_IGNORE_RULES)


@pytest.mark.parametrize(("hours", "passes"), [(120, True), (121, False), (100000, False)])
def test_database_age_limit_has_a_hard_ceiling(hours: int, passes: bool) -> None:
    report = grype_report()
    report["descriptor"]["configuration"]["db"]["max-allowed-built-age"] = hours * 3600 * 10**9
    settings = gate.GateSettings(
        "0.121.0", 6, timedelta(hours=hours), IMAGE_ID, ("alpine", "3.24.3"), EXPECTED_CONFIG
    )
    failures = gate.evaluate(gate.parse_report(report), (), settings, NOW).failures
    assert (failures == ()) is passes
    if not passes:
        assert failures == (
            f"the database age limit of {hours} hours exceeds the gate's 120-hour ceiling",
        )


def test_main_refuses_a_database_age_above_the_ceiling(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report, exceptions = write_inputs(tmp_path, grype_report())
    arguments = cli_arguments(report, exceptions)
    arguments[arguments.index("--max-db-age-hours") + 1] = "100000"
    assert gate.main(arguments, now=NOW) == 1
    assert "exceeds the gate's 120-hour ceiling" in capsys.readouterr().out


def test_committed_expected_configuration_has_placeholders_for_variable_fields() -> None:
    assert EXPECTED_CONFIG["file"] == ""
    assert EXPECTED_CONFIG["db"]["cache-dir"] == ""
    assert set(gate.VARIABLE_FIELDS) == {"file", "db.cache-dir"}


@pytest.mark.parametrize(
    ("ignored", "count"), [([{"vulnerability": {"id": "CVE-1"}}], "1"), ("all", "?")]
)
def test_ignored_matches_fail(ignored: object, count: str) -> None:
    report = grype_report()
    report["ignoredMatches"] = ignored
    assert decide(report).failures == (
        f"the report has {count} ignored match(es); the gate allows no ignore rules",
    )


def test_empty_ignored_matches_pass() -> None:
    report = grype_report()
    report["ignoredMatches"] = []
    assert decide(report).passed


def without(document: dict[str, Any], *path: str | int) -> dict[str, Any]:
    changed = deepcopy(document)
    node: Any = changed
    for step in path[:-1]:
        node = node[step]
    del node[path[-1]]
    return changed


def replaced(document: dict[str, Any], value: object, *path: str | int) -> dict[str, Any]:
    changed = deepcopy(document)
    node: Any = changed
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    return changed


BASE: Final[dict[str, Any]] = grype_report(grype_match("GO-1"))


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "report must be an object"),
        (without(BASE, "descriptor"), "descriptor must be an object"),
        (without(BASE, "matches"), "report.matches must be an array"),
        (replaced(BASE, {}, "matches"), "report.matches must be an array"),
        (replaced(BASE, ["x"], "matches"), "matches[0] must be an object"),
        (without(BASE, "matches", 0, "vulnerability"), "matches[0].vulnerability must be"),
        (without(BASE, "matches", 0, "artifact"), "matches[0].artifact must be an object"),
        (
            without(BASE, "matches", 0, "vulnerability", "fix"),
            "matches[0].vulnerability.fix must be an object",
        ),
        (
            replaced(BASE, "Severe", "matches", 0, "vulnerability", "severity"),
            "matches[0].vulnerability.severity 'severe' is not a known Grype severity",
        ),
        (
            replaced(BASE, 7, "matches", 0, "vulnerability", "severity"),
            "matches[0].vulnerability.severity must be a string",
        ),
        (
            without(BASE, "matches", 0, "vulnerability", "id"),
            "matches[0].vulnerability.id must be a string",
        ),
        (
            replaced(BASE, None, "matches", 0, "artifact", "version"),
            "matches[0].artifact.version must be a string",
        ),
        (
            replaced(BASE, [1], "matches", 0, "vulnerability", "fix", "versions"),
            "matches[0].vulnerability.fix.versions must contain only strings",
        ),
        (
            replaced(BASE, ["/x"], "matches", 0, "artifact", "locations"),
            "matches[0].artifact.locations[] must be an object",
        ),
        (
            replaced(BASE, [{"layerID": "sha256:0"}], "matches", 0, "artifact", "locations"),
            "matches[0].artifact.path must be a string",
        ),
        (
            replaced(BASE, "x", "descriptor", "configuration"),
            "descriptor.configuration must be an object",
        ),
        (without(BASE, "descriptor", "db"), "descriptor.db must be an object"),
        (without(BASE, "descriptor", "db", "status"), "descriptor.db.status must be an object"),
        (without(BASE, "source"), "source must be an object"),
        (without(BASE, "source", "target"), "source.target must be an object"),
        (without(BASE, "distro"), "distro must be an object"),
        (without(BASE, "distro", "name"), "distro.name must be a string"),
        (without(BASE, "distro", "version"), "distro.version must be a string"),
        (
            without(BASE, "source", "target", "imageID"),
            "source.target.imageID must be a string",
        ),
        (
            replaced(BASE, "x", "source", "target", "repoDigests"),
            "source.target.repoDigests must be an array",
        ),
        (
            replaced(BASE, [1], "source", "target", "repoDigests"),
            "source.target.repoDigests must contain only strings",
        ),
        (
            replaced(BASE, "yes", "descriptor", "db", "status", "valid"),
            "descriptor.db.status.valid must be a boolean",
        ),
        (
            replaced(BASE, "yesterday", "descriptor", "db", "status", "built"),
            "descriptor.db.status.built 'yesterday' is not an RFC 3339 timestamp",
        ),
        (
            replaced(BASE, "2026-10-25T06:27:34", "descriptor", "db", "status", "built"),
            "descriptor.db.status.built '2026-10-25T06:27:34' has no time zone",
        ),
        (
            without(BASE, "descriptor", "db", "status", "schemaVersion"),
            "descriptor.db.status.schemaVersion must be a string",
        ),
        (without(BASE, "descriptor", "version"), "descriptor.version must be a string"),
    ],
)
def test_malformed_report_is_rejected(document: object, message: str) -> None:
    with pytest.raises(gate.ReportError) as caught:
        gate.parse_report(document)
    assert message in str(caught.value)


def test_parsed_finding_fields() -> None:
    finding = gate.parse_report(
        grype_report(at_locations(grype_match("GO-1"), "/b", "/a", "/b"))
    ).findings[0]
    assert finding == gate.Finding(
        vulnerability_id="GO-1",
        package="golang.org/x/net",
        version="v0.57.0",
        package_type="go-module",
        severity="high",
        fix_state="fixed",
        fix_versions=("0.60.0",),
        locations=("/a", "/b"),
    )
    assert finding.key == ("GO-1", "golang.org/x/net", "v0.57.0")
    assert finding.label == "high GO-1 in golang.org/x/net v0.57.0"
    assert finding.fix == "fixed (0.60.0)"


def test_load_report_reads_json(tmp_path: Path) -> None:
    path = tmp_path / "grype.json"
    path.write_text(json.dumps(grype_report()), encoding="utf-8")
    assert gate.load_report(path).grype_version == "0.121.0"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"{not json", "is not valid JSON"),
        (b'{"matches": [], "matches": []}', "duplicate JSON key 'matches'"),
        (b"\xff\xfe", "cannot read the Grype report"),
    ],
)
def test_load_report_rejects_unreadable_input(tmp_path: Path, content: bytes, message: str) -> None:
    path = tmp_path / "grype.json"
    path.write_bytes(content)
    with pytest.raises(gate.ReportError, match=message):
        gate.load_report(path)


def test_load_report_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(gate.ReportError, match="cannot read the Grype report"):
        gate.load_report(tmp_path / "missing.json")


def test_summary_of_a_passing_run() -> None:
    report = gate.parse_report(
        grype_report(
            grype_match("GO-2026-6612", severity="Critical"),
            grype_match("CVE-2026-1", "busybox", "1.37.0-r31", "Medium"),
        )
    )
    decision = gate.evaluate(
        report, (accepted("GO-2026-6612", severity="critical"),), SETTINGS, NOW
    )
    summary = gate.render_summary(decision, report, SETTINGS, NOW)
    assert summary.startswith("# Image vulnerability gate: PASSED\n")
    assert "| Gate run | 2026-10-26T12:00:00Z |" in summary
    assert "| Scanned image | localhost/linux-compliance-runner:smoke |" in summary
    assert (
        "| Vulnerability database | schema v6.1.10, built 2026-10-25T06:27:34Z, 29.5 h old "
        "(limit 120 h) |"
    ) in summary
    assert (
        "| Findings | 2 (1 critical, 0 high, 1 medium, 0 low, 0 negligible, 0 unknown) |" in summary
    )
    assert "| Accepted by exceptions | 1 |" in summary
    assert (
        "| GO-2026-6612 | golang.org/x/net | v0.57.0 | critical | fixed (0.60.0) | FREES-37 | "
        "2027-01-23 |"
    ) in summary
    assert "## Failures" not in summary


def test_summary_escapes_hostile_values() -> None:
    hostile = grype_match("CVE-1|`x`\n# heading", "pkg<script>", "1.0*", "High")
    report = gate.parse_report(grype_report(hostile))
    decision = gate.evaluate(report, (), SETTINGS, NOW)
    summary = gate.render_summary(decision, report, SETTINGS, NOW)
    assert summary.startswith("# Image vulnerability gate: FAILED\n")
    assert "\n# heading" not in summary
    assert "<script>" not in summary
    assert "- unlisted high CVE-1\\|\\`x\\` \\# heading in pkg\\<script\\> 1.0\\*" in summary


def test_summary_without_a_report() -> None:
    decision = gate.Decision(failures=("input: broken",))
    summary = gate.render_summary(decision, None, SETTINGS, NOW)
    assert "Scanned image" not in summary
    assert "## Failures\n\n- input: broken\n" in summary


def test_main_passes_and_writes_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report, exceptions = write_inputs(
        tmp_path, grype_report(grype_match("GO-2026-6612", severity="Critical")), exception_entry()
    )
    summary = tmp_path / "out" / "summary.md"
    status = gate.main(cli_arguments(report, exceptions, "--summary", str(summary)), now=NOW)
    assert status == 0
    written = summary.read_text(encoding="utf-8")
    assert written.startswith("# Image vulnerability gate: PASSED")
    assert capsys.readouterr().out == written


def test_main_fails_on_expired_entry(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report, exceptions = write_inputs(
        tmp_path,
        grype_report(grype_match("GO-2026-6612", severity="Critical")),
        exception_entry(created="2026-08-01", expires="2026-10-26"),
    )
    assert gate.main(cli_arguments(report, exceptions), now=NOW) == 1
    output = capsys.readouterr().out
    assert "exceptions file: exceptions\\[0\\] ('GO-2026-6612'): entry has expired" in output
    assert "unlisted critical GO-2026-6612" in output


def test_main_fails_on_malformed_exceptions_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report, exceptions = write_inputs(tmp_path, grype_report())
    exceptions.write_text("---\nformat: 2\nformat: 2\nexceptions: []\n", encoding="utf-8")
    assert gate.main(cli_arguments(report, exceptions), now=NOW) == 1
    assert "exceptions file: line 3: duplicate key 'format'" in capsys.readouterr().out


def test_main_fails_on_malformed_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report, exceptions = write_inputs(tmp_path, {"matches": []})
    assert gate.main(cli_arguments(report, exceptions), now=NOW) == 1
    output = capsys.readouterr().out
    assert "- input: descriptor must be an object" in output
    assert "Scanned image" not in output


def test_main_fails_on_stale_database(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report, exceptions = write_inputs(tmp_path, grype_report())
    later = datetime(2026, 11, 1, tzinfo=UTC)
    assert gate.main(cli_arguments(report, exceptions), now=later) == 1
    assert "a stale database can hide new findings" in capsys.readouterr().out


def test_main_uses_the_current_time(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    current = datetime.now(tz=UTC)
    document = grype_report()
    document["descriptor"]["db"]["status"]["built"] = current.isoformat()
    report, exceptions = write_inputs(tmp_path, document)
    assert gate.main(cli_arguments(report, exceptions)) == 0
    assert "PASSED" in capsys.readouterr().out


@pytest.mark.parametrize("value", ["0", "-1", "five"])
def test_main_rejects_invalid_numbers(
    tmp_path: Path, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    report, exceptions = write_inputs(tmp_path, grype_report())
    arguments = cli_arguments(report, exceptions)
    arguments[arguments.index("--max-db-age-hours") + 1] = value
    with pytest.raises(SystemExit) as caught:
        gate.main(arguments, now=NOW)
    assert caught.value.code == 2
    assert "--max-db-age-hours" in capsys.readouterr().err


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    report, exceptions = write_inputs(tmp_path, grype_report(grype_match("GO-1")))
    monkeypatch.setattr(sys, "argv", ["grype_gate", *cli_arguments(report, exceptions)])
    monkeypatch.delitem(sys.modules, "tools.security.grype_gate", raising=False)
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("tools.security.grype_gate", run_name="__main__")
    assert caught.value.code == 1
