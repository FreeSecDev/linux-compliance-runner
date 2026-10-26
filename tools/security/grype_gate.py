"""Fail-closed vulnerability gate over a Grype JSON report.

The gate reads the Grype JSON report of the image and the exceptions file
``security/vulnerability-exceptions.yaml`` and fails when:

* the exceptions file breaks the schema, or an entry has expired
  (validated by :mod:`tools.security.vulnerability_exceptions`);
* a critical, high or unknown-severity finding is not listed, where a listing
  matches on vulnerability ID, package name and package version together;
* a listed entry matches no reported finding (a stale entry);
* a listed finding is now reported with a different severity;
* the report is malformed, comes from another Grype version, describes another
  image, distribution or distribution release, has ignored matches, or its
  effective Grype configuration differs in any way from the committed expected
  configuration (``security/grype-expected-config.json``) outside the fields
  listed in :data:`VARIABLE_FIELDS`, including any new or unknown setting;
* the effective or the expected configuration breaks a hard invariant in
  :data:`INVARIANTS` (settings that hide findings or weaken matching), which
  no regenerated expected configuration can relax;
* the vulnerability database is invalid, has another schema, was built in the
  future or is older than the allowed age.

A Markdown summary is printed and, with ``--summary``, written to a file.
Exit status: 0 when the gate passes, 1 when it fails, 2 for usage errors.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from tools.security.vulnerability_exceptions import VulnerabilityException, validate_file

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

DESCRIPTION: Final[str] = "Fail-closed vulnerability gate over a Grype JSON report."
GATED_SEVERITIES: Final[frozenset[str]] = frozenset({"critical", "high", "unknown"})
GRYPE_SEVERITIES: Final[tuple[str, ...]] = (
    "critical",
    "high",
    "medium",
    "low",
    "negligible",
    "unknown",
)
VARIABLE_FIELDS: Final[dict[str, str]] = {
    "db.cache-dir": (
        "absolute path of the database cache inside the checkout; the database itself is "
        "checked through descriptor.db.status"
    ),
    "file": "path the report was written to; it does not influence matching",
}
DERIVED_MAX_AGE_FIELD: Final[tuple[str, str]] = ("db", "max-allowed-built-age")
NANOSECONDS_PER_SECOND: Final[int] = 1_000_000_000
MAX_DB_AGE_HOURS_CEILING: Final[int] = 120


def _builtin_ignore_rule(name: str, package_type: str, upstream: str) -> dict[str, object]:
    """Return one of Grype's built-in kernel-header ignore rules as it appears in a report."""
    return {
        "vulnerability": "",
        "include-aliases": False,
        "reason": "",
        "namespace": "",
        "fix-state": "",
        "package": {
            "name": name,
            "version": "",
            "language": "",
            "type": package_type,
            "location": "",
            "upstream-name": upstream,
        },
        "vex-status": "",
        "vex-justification": "",
        "match-type": "exact-indirect-match",
    }


BUILTIN_IGNORE_RULES: Final[tuple[dict[str, object], ...]] = (
    _builtin_ignore_rule("kernel-headers", "rpm", "kernel"),
    _builtin_ignore_rule("linux(-.*)?-headers-.*", "deb", "linux.*"),
    _builtin_ignore_rule("linux-libc-dev", "deb", "linux"),
    _builtin_ignore_rule("linux-kbuild-.*", "deb", "linux.*"),
)
INVARIANTS: Final[tuple[tuple[tuple[str, ...], object], ...]] = (
    (("only-fixed",), False),
    (("only-notfixed",), False),
    (("ignore-wontfix",), ""),
    (("exclude",), []),
    (("vex-documents",), []),
    (("vex-add",), []),
    (("ignore",), list(BUILTIN_IGNORE_RULES)),
    (("distro",), ""),
    (("platform",), ""),
    (("default-image-pull-source",), ""),
    (("by-cve",), False),
    (("search", "indexed-archives"), True),
    (("match", "stock", "using-cpes"), True),
    (("match", "jvm", "using-cpes"), True),
    (("db", "auto-update"), False),
    (("db", "validate-age"), True),
    (("db", "validate-by-hash-on-start"), True),
)
EMPTY_FROM_VALUES: Final[tuple[object, ...]] = (None, [])
SEARCH_SCOPES: Final[frozenset[str]] = frozenset({"squashed", "all-layers"})
MISSING: Final[object] = object()
CLOCK_SKEW: Final[timedelta] = timedelta(minutes=5)
DIGEST: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}")
MARKDOWN_SPECIAL: Final[re.Pattern[str]] = re.compile(r"([\\`*_\[\]<>#|~])")
LINE_BREAKS: Final[re.Pattern[str]] = re.compile(r"\s+")


class ReportError(ValueError):
    """The Grype report is not the JSON structure the gate expects."""


@dataclass(frozen=True, slots=True)
class Finding:
    """One Grype match: a vulnerability reported for one package."""

    vulnerability_id: str
    package: str
    version: str
    package_type: str
    severity: str
    fix_state: str
    fix_versions: tuple[str, ...]
    locations: tuple[str, ...]

    @property
    def key(self) -> tuple[str, str, str]:
        """Return the ``(vulnerability ID, package, version)`` match key."""
        return (self.vulnerability_id, self.package, self.version)

    @property
    def label(self) -> str:
        """Return a short human-readable description of the finding."""
        return f"{self.severity} {self.vulnerability_id} in {self.package} {self.version}"

    @property
    def fix(self) -> str:
        """Return the fix state and the fixed versions, if any."""
        if self.fix_versions:
            return f"{self.fix_state} ({', '.join(self.fix_versions)})"
        return self.fix_state


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The parts of a Grype JSON report that the gate evaluates."""

    grype_version: str
    image: str
    image_digests: frozenset[str]
    distro: tuple[str, str]
    db_schema: str
    db_built: datetime
    db_valid: bool
    configuration: dict[str, object]
    suppressions: tuple[str, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class GateSettings:
    """What the report must show for the gate to trust it."""

    grype_version: str
    db_schema: int
    max_db_age: timedelta
    image_id: str
    distro: tuple[str, str]
    expected_configuration: dict[str, object]


@dataclass(frozen=True, slots=True)
class Decision:
    """The gate outcome."""

    failures: tuple[str, ...]
    accepted: tuple[tuple[Finding, VulnerabilityException], ...] = field(default=())

    @property
    def passed(self) -> bool:
        """Return whether the gate passes."""
        return not self.failures


def _object(value: object, where: str) -> dict[str, object]:
    """Return ``value`` as a JSON object or raise :class:`ReportError`."""
    if not isinstance(value, dict):
        message = f"{where} must be an object"
        raise ReportError(message)
    return cast("dict[str, object]", value)


def _string(container: Mapping[str, object], key: str, where: str) -> str:
    """Return the string at ``key`` or raise :class:`ReportError`."""
    value = container.get(key)
    if not isinstance(value, str):
        message = f"{where}.{key} must be a string"
        raise ReportError(message)
    return value


def _array(container: Mapping[str, object], key: str, where: str) -> list[object]:
    """Return the list at ``key`` or raise :class:`ReportError`."""
    value = container.get(key)
    if not isinstance(value, list):
        message = f"{where}.{key} must be an array"
        raise ReportError(message)
    return cast("list[object]", value)


def _strings(values: Iterable[object], where: str) -> tuple[str, ...]:
    """Return every value as a string or raise :class:`ReportError`."""
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            message = f"{where} must contain only strings"
            raise ReportError(message)
        result.append(value)
    return tuple(result)


def parse_finding(value: object, where: str) -> Finding:
    """Parse one entry of the report's ``matches`` array."""
    match = _object(value, where)
    vulnerability = _object(match.get("vulnerability"), f"{where}.vulnerability")
    artifact = _object(match.get("artifact"), f"{where}.artifact")
    fix = _object(vulnerability.get("fix"), f"{where}.vulnerability.fix")
    severity = _string(vulnerability, "severity", f"{where}.vulnerability").lower()
    if severity not in GRYPE_SEVERITIES:
        message = f"{where}.vulnerability.severity {severity!r} is not a known Grype severity"
        raise ReportError(message)
    locations = [
        _string(_object(item, f"{where}.artifact.locations[]"), "path", f"{where}.artifact")
        for item in _array(artifact, "locations", f"{where}.artifact")
    ]
    return Finding(
        vulnerability_id=_string(vulnerability, "id", f"{where}.vulnerability"),
        package=_string(artifact, "name", f"{where}.artifact"),
        version=_string(artifact, "version", f"{where}.artifact"),
        package_type=_string(artifact, "type", f"{where}.artifact"),
        severity=severity,
        fix_state=_string(fix, "state", f"{where}.vulnerability.fix"),
        fix_versions=_strings(
            _array(fix, "versions", f"{where}.vulnerability.fix"),
            f"{where}.vulnerability.fix.versions",
        ),
        locations=tuple(sorted(set(locations))),
    )


def _ignored_matches(report: Mapping[str, object]) -> list[str]:
    """Describe ignored matches; the gate allows no ignore rule to take effect."""
    ignored = report.get("ignoredMatches", [])
    if ignored == []:
        return []
    count = len(cast("list[object]", ignored)) if isinstance(ignored, list) else "?"
    return [f"the report has {count} ignored match(es); the gate allows no ignore rules"]


def _json(value: object) -> str:
    """Render a configuration value as compact JSON for a failure message."""
    return json.dumps(value, sort_keys=True)


def _object_differences(actual: object, expected: dict[str, object], path: str) -> list[str]:
    """Compare two JSON objects key by key."""
    if not isinstance(actual, dict):
        return [f"{path or '<root>'}: expected an object, got {_json(actual)}"]
    found = cast("dict[str, object]", actual)
    differences: list[str] = []
    for key in sorted(set(expected) | set(found)):
        child = f"{path}.{key}" if path else key
        if key not in found:
            differences.append(f"{child} is missing")
        elif key not in expected:
            differences.append(f"{child} is a new or unknown setting ({_json(found[key])})")
        else:
            differences.extend(configuration_differences(found[key], expected[key], child))
    return differences


def _list_differences(actual: object, expected: list[object], path: str) -> list[str]:
    """Compare two JSON arrays element by element."""
    shown = _json(actual)
    items = cast("list[object]", actual) if isinstance(actual, list) else None
    if items is None or len(items) != len(expected):
        return [f"{path}: expected {_json(expected)}, got {shown}"]
    differences: list[str] = []
    for index, (value, wanted) in enumerate(zip(items, expected, strict=True)):
        differences.extend(configuration_differences(value, wanted, f"{path}[{index}]"))
    return differences


def configuration_differences(actual: object, expected: object, path: str = "") -> list[str]:
    """Return every difference between the effective and the expected configuration.

    Objects must have exactly the same keys, arrays the same length and scalars
    the same type and value. Fields in :data:`VARIABLE_FIELDS` only need to be
    non-empty strings.
    """
    if path in VARIABLE_FIELDS:
        if isinstance(actual, str) and actual:
            return []
        return [f"{path} must be a non-empty string, got {_json(actual)}"]
    if isinstance(expected, dict):
        return _object_differences(actual, cast("dict[str, object]", expected), path)
    if isinstance(expected, list):
        return _list_differences(actual, cast("list[object]", expected), path)
    if type(actual) is not type(expected) or actual != expected:
        return [f"{path}: expected {_json(expected)}, got {_json(actual)}"]
    return []


def _as_object(value: object) -> dict[str, object] | None:
    """Return ``value`` as a JSON object, or None when it is not one."""
    return cast("dict[str, object]", value) if isinstance(value, dict) else None


def _lookup(configuration: Mapping[str, object], path: Sequence[str]) -> object:
    """Return the value at ``path`` in a nested configuration, or :data:`MISSING`."""
    node: object = dict(configuration)
    for step in path:
        container = _as_object(node)
        if container is None:
            return MISSING
        node = container.get(step, MISSING)
    return node


def _shown(value: object) -> str:
    """Render a looked-up value, naming a missing one."""
    return "<missing>" if value is MISSING else _json(value)


def invariant_violations(configuration: Mapping[str, object]) -> list[str]:
    """Return every hard invariant that ``configuration`` breaks.

    The invariants hold whatever the expected configuration file says, so a
    regenerated expected file can never relax them; changing one needs a change
    to this module and its review.
    """
    violations = [
        f"{'.'.join(path)} must be {_json(required)}, got {_shown(value)}"
        for path, required in INVARIANTS
        if (value := _lookup(configuration, path)) is MISSING
        or configuration_differences(value, required, ".".join(path))
    ]
    origin = _lookup(configuration, ("from",))
    if origin is MISSING or not any(
        type(origin) is type(empty) and origin == empty for empty in EMPTY_FROM_VALUES
    ):
        violations.append(f"from must be null or [], got {_shown(origin)}")
    scope = _lookup(configuration, ("search", "scope"))
    if not isinstance(scope, str) or scope not in SEARCH_SCOPES:
        violations.append(
            f"search.scope must be one of {', '.join(sorted(SEARCH_SCOPES))}, got {_shown(scope)}"
        )
    return violations


def expected_configuration_for(
    expected: Mapping[str, object], max_db_age: timedelta
) -> dict[str, object]:
    """Return a copy of the expected configuration with the database age limit filled in."""
    result = cast("dict[str, object]", json.loads(json.dumps(expected)))
    section, key = DERIVED_MAX_AGE_FIELD
    database = result.get(section)
    if isinstance(database, dict):
        cast("dict[str, object]", database)[key] = (
            int(max_db_age.total_seconds()) * NANOSECONDS_PER_SECOND
        )
    return result


def _image_digests(target: Mapping[str, object]) -> frozenset[str]:
    """Return every digest under which the report identifies the image."""
    digests = {_string(target, "imageID", "source.target")}
    manifest = target.get("manifestDigest")
    if isinstance(manifest, str):
        digests.add(manifest)
    repo_digests: tuple[str, ...] = ()
    if "repoDigests" in target:
        repo_digests = _strings(
            _array(target, "repoDigests", "source.target"), "source.target.repoDigests"
        )
    digests.update(digest.rpartition("@")[2] for digest in repo_digests)
    return frozenset(digest for digest in digests if DIGEST.fullmatch(digest))


def _db_built(status: Mapping[str, object]) -> datetime:
    """Return the timezone-aware build time of the vulnerability database."""
    built = _string(status, "built", "descriptor.db.status")
    try:
        parsed = datetime.fromisoformat(built)
    except ValueError as error:
        message = f"descriptor.db.status.built {built!r} is not an RFC 3339 timestamp"
        raise ReportError(message) from error
    if parsed.tzinfo is None:
        message = f"descriptor.db.status.built {built!r} has no time zone"
        raise ReportError(message)
    return parsed


def parse_report(document: object) -> ScanReport:
    """Parse the Grype JSON document.

    Raises:
        ReportError: a required field is missing or has the wrong type.
    """
    report = _object(document, "report")
    descriptor = _object(report.get("descriptor"), "descriptor")
    configuration = _object(descriptor.get("configuration"), "descriptor.configuration")
    status = _object(
        _object(descriptor.get("db"), "descriptor.db").get("status"), "descriptor.db.status"
    )
    target = _object(_object(report.get("source"), "source").get("target"), "source.target")
    distro = _object(report.get("distro"), "distro")
    valid = status.get("valid")
    if not isinstance(valid, bool):
        message = "descriptor.db.status.valid must be a boolean"
        raise ReportError(message)
    return ScanReport(
        grype_version=_string(descriptor, "version", "descriptor"),
        image=_string(target, "userInput", "source.target"),
        image_digests=_image_digests(target),
        distro=(_string(distro, "name", "distro"), _string(distro, "version", "distro")),
        db_schema=_string(status, "schemaVersion", "descriptor.db.status"),
        db_built=_db_built(status),
        db_valid=valid,
        configuration=configuration,
        suppressions=tuple(_ignored_matches(report)),
        findings=tuple(
            parse_finding(item, f"matches[{index}]")
            for index, item in enumerate(_array(report, "matches", "report"))
        ),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object, rejecting duplicate keys instead of keeping the last."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = f"duplicate JSON key {key!r}"
            raise ReportError(message)
        result[key] = value
    return result


def load_json(path: Path, what: str) -> object:
    """Read the JSON document at ``path``, rejecting duplicate keys.

    Raises:
        ReportError: the file cannot be read or is not valid JSON.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        message = f"cannot read the {what} {path}: {error}"
        raise ReportError(message) from error
    try:
        return cast("object", json.loads(text, object_pairs_hook=_reject_duplicate_keys))
    except json.JSONDecodeError as error:
        message = f"the {what} {path} is not valid JSON: {error}"
        raise ReportError(message) from error


def load_report(path: Path) -> ScanReport:
    """Read and parse the Grype JSON report at ``path``.

    Raises:
        ReportError: the file cannot be read, is not JSON or is malformed.
    """
    return parse_report(load_json(path, "Grype report"))


def load_expected_configuration(path: Path) -> dict[str, object]:
    """Read the committed expected Grype configuration at ``path``.

    Raises:
        ReportError: the file cannot be read, is not JSON or is not an object.
    """
    return _object(load_json(path, "expected Grype configuration"), "expected configuration")


def provenance_failures(report: ScanReport, settings: GateSettings, now: datetime) -> list[str]:
    """Return why the report cannot be trusted as a scan of the expected image."""
    failures: list[str] = []
    if report.grype_version != settings.grype_version:
        failures.append(
            f"report was produced by Grype {report.grype_version}, "
            f"expected the pinned {settings.grype_version}"
        )
    if settings.image_id not in report.image_digests:
        failures.append(f"report does not describe the image {settings.image_id}")
    if report.distro != settings.distro:
        failures.append(
            f"report detected distribution {' '.join(report.distro)!r}, "
            f"expected {' '.join(settings.distro)!r}"
        )
    failures.extend(report.suppressions)
    if settings.max_db_age > timedelta(hours=MAX_DB_AGE_HOURS_CEILING):
        failures.append(
            f"the database age limit of {settings.max_db_age.total_seconds() / 3600:.0f} hours "
            f"exceeds the gate's {MAX_DB_AGE_HOURS_CEILING}-hour ceiling"
        )
    failures.extend(
        f"Grype configuration breaks a gate invariant: {violation}"
        for violation in invariant_violations(report.configuration)
    )
    failures.extend(
        f"expected configuration file breaks a gate invariant: {violation}"
        for violation in invariant_violations(settings.expected_configuration)
    )
    failures.extend(
        f"Grype configuration differs from the expected configuration: {difference}"
        for difference in configuration_differences(
            report.configuration,
            expected_configuration_for(settings.expected_configuration, settings.max_db_age),
        )
    )
    if not report.db_valid:
        failures.append("Grype reports the vulnerability database as invalid")
    if re.fullmatch(rf"v{settings.db_schema}\.[0-9]+\.[0-9]+", report.db_schema) is None:
        failures.append(
            f"vulnerability database schema {report.db_schema!r} is not v{settings.db_schema}"
        )
    age = now - report.db_built
    if age < -CLOCK_SKEW:
        failures.append(
            f"vulnerability database build time {_timestamp(report.db_built)} is in the future"
        )
    elif age > settings.max_db_age:
        failures.append(
            f"vulnerability database built {_timestamp(report.db_built)} is "
            f"{age.total_seconds() / 3600:.1f} hours old, more than the "
            f"{settings.max_db_age.total_seconds() / 3600:.0f}-hour limit; a stale database "
            "can hide new findings"
        )
    return failures


def finding_failures(
    findings: Sequence[Finding], exceptions: Sequence[VulnerabilityException]
) -> tuple[list[str], list[tuple[Finding, VulnerabilityException]]]:
    """Match findings against the exceptions.

    Returns:
        The failures and the accepted ``(finding, exception)`` pairs.
    """
    listed = {entry.key: entry for entry in exceptions}
    listed_ids: dict[str, list[VulnerabilityException]] = {}
    for entry in exceptions:
        listed_ids.setdefault(entry.vulnerability_id, []).append(entry)
    failures: list[str] = []
    accepted: list[tuple[Finding, VulnerabilityException]] = []
    for finding in findings:
        listing = listed.get(finding.key)
        if listing is None:
            if finding.severity in GATED_SEVERITIES:
                failures.append(
                    _unlisted_message(finding, listed_ids.get(finding.vulnerability_id, []))
                )
            continue
        if listing.severity != finding.severity:
            failures.append(
                f"{listing.label} is listed as {listing.severity} but reported as "
                f"{finding.severity}; re-assess the exception"
            )
            continue
        accepted.append((finding, listing))
    accepted.sort(key=lambda pair: (GRYPE_SEVERITIES.index(pair[0].severity), pair[0].key))
    reported = {finding.key for finding in findings}
    failures.extend(
        f"stale exception: {entry.label} ({entry.jira}) is no longer reported; remove the entry"
        for entry in exceptions
        if entry.key not in reported
    )
    return failures, accepted


def _unlisted_message(finding: Finding, same_id: Sequence[VulnerabilityException]) -> str:
    """Describe an unlisted critical or high finding."""
    message = (
        f"unlisted {finding.label} ({finding.package_type}) at "
        f"{', '.join(finding.locations) or '<no location>'}; fix: {finding.fix}"
    )
    if same_id:
        others = ", ".join(f"{entry.package} {entry.version}" for entry in same_id)
        message += f"; {finding.vulnerability_id} is listed only for {others}"
    return message


def evaluate(
    report: ScanReport,
    exceptions: Sequence[VulnerabilityException],
    settings: GateSettings,
    now: datetime,
) -> Decision:
    """Apply every gate rule to a parsed report and validated exceptions."""
    matched, accepted = finding_failures(report.findings, exceptions)
    return Decision(
        failures=(*provenance_failures(report, settings, now), *matched),
        accepted=tuple(accepted),
    )


def _timestamp(value: datetime) -> str:
    """Format ``value`` as an RFC 3339 UTC timestamp with second precision."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cell(value: str) -> str:
    """Escape ``value`` for a single Markdown table cell or list item."""
    return MARKDOWN_SPECIAL.sub(r"\\\1", LINE_BREAKS.sub(" ", value)).strip()


def render_summary(
    decision: Decision, report: ScanReport | None, settings: GateSettings, now: datetime
) -> str:
    """Render the Markdown summary of the gate run."""
    verdict = "PASSED" if decision.passed else "FAILED"
    lines = [f"# Image vulnerability gate: {verdict}", "", "| Item | Value |", "|---|---|"]
    lines.append(f"| Gate run | {_timestamp(now)} |")
    lines.append(f"| Expected image | {_cell(settings.image_id)} |")
    if report is not None:
        age = (now - report.db_built).total_seconds() / 3600
        counts = Counter(finding.severity for finding in report.findings)
        breakdown = ", ".join(f"{counts[name]} {name}" for name in GRYPE_SEVERITIES)
        lines.extend(
            [
                f"| Scanned image | {_cell(report.image)} |",
                f"| Distribution | {_cell(' '.join(report.distro))} |",
                f"| Grype | {_cell(report.grype_version)} |",
                (
                    f"| Vulnerability database | schema {_cell(report.db_schema)}, built "
                    f"{_cell(_timestamp(report.db_built))}, {age:.1f} h old "
                    f"(limit {settings.max_db_age.total_seconds() / 3600:.0f} h) |"
                ),
                f"| Findings | {len(report.findings)} ({breakdown}) |",
            ]
        )
    lines.append(f"| Accepted by exceptions | {len(decision.accepted)} |")
    if decision.failures:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {_cell(failure)}" for failure in decision.failures)
    if decision.accepted:
        lines.extend(
            [
                "",
                "## Accepted findings",
                "",
                "| ID | Package | Version | Severity | Fix | Jira | Expires |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        lines.extend(
            f"| {_cell(finding.vulnerability_id)} | {_cell(finding.package)} | "
            f"{_cell(finding.version)} | {finding.severity} | {_cell(finding.fix)} | "
            f"{_cell(entry.jira)} | {entry.expires.isoformat()} |"
            for finding, entry in decision.accepted
        )
    return "\n".join(lines) + "\n"


def _settings(arguments: argparse.Namespace, expected: dict[str, object]) -> GateSettings:
    """Build the gate settings from the command line and the expected configuration."""
    return GateSettings(
        grype_version=arguments.grype_version,
        db_schema=arguments.db_schema,
        max_db_age=timedelta(hours=arguments.max_db_age_hours),
        image_id=arguments.image_id,
        distro=(arguments.distro, arguments.distro_version),
        expected_configuration=expected,
    )


def run(arguments: argparse.Namespace, now: datetime) -> tuple[Decision, str]:
    """Run the gate for parsed command-line arguments."""
    exceptions, problems = validate_file(arguments.exceptions, now.astimezone(UTC).date())
    exception_failures = [f"exceptions file: {problem}" for problem in problems]
    expected: dict[str, object] = {}
    try:
        expected = load_expected_configuration(arguments.expected_config)
        report = load_report(arguments.report)
    except ReportError as error:
        settings = _settings(arguments, expected)
        decision = Decision(failures=(*exception_failures, f"input: {error}"))
        return decision, render_summary(decision, None, settings, now)
    settings = _settings(arguments, expected)
    evaluated = evaluate(report, exceptions, settings, now)
    decision = Decision(
        failures=(*exception_failures, *evaluated.failures), accepted=evaluated.accepted
    )
    return decision, render_summary(decision, report, settings, now)


def _positive_int(value: str) -> int:
    """Parse a strictly positive integer command-line value."""
    try:
        number = int(value)
    except ValueError as error:
        message = f"{value!r} is not an integer"
        raise argparse.ArgumentTypeError(message) from error
    if number <= 0:
        message = f"{value!r} must be greater than zero"
        raise argparse.ArgumentTypeError(message)
    return number


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser."""
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--report", type=Path, required=True, help="Grype JSON report.")
    parser.add_argument("--exceptions", type=Path, required=True, help="Exceptions YAML file.")
    parser.add_argument("--summary", type=Path, help="Write the Markdown summary to this file.")
    parser.add_argument("--grype-version", required=True, help="Pinned Grype version.")
    parser.add_argument("--db-schema", type=_positive_int, required=True, help="DB schema major.")
    parser.add_argument(
        "--max-db-age-hours", type=_positive_int, required=True, help="Maximum DB age in hours."
    )
    parser.add_argument("--image-id", required=True, help="Image ID or digest that was scanned.")
    parser.add_argument("--distro", required=True, help="Expected distribution name.")
    parser.add_argument(
        "--distro-version", required=True, help="Expected distribution release of the image."
    )
    parser.add_argument(
        "--expected-config",
        type=Path,
        required=True,
        help="Committed expected Grype configuration (JSON).",
    )
    return parser


def main(argv: Sequence[str] | None = None, now: datetime | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    arguments = build_parser().parse_args(argv)
    decision, summary = run(arguments, now or datetime.now(tz=UTC))
    print(summary, end="")
    if arguments.summary is not None:
        arguments.summary.parent.mkdir(parents=True, exist_ok=True)
        arguments.summary.write_text(summary, encoding="utf-8")
    return 0 if decision.passed else 1


if __name__ == "__main__":
    sys.exit(main())
