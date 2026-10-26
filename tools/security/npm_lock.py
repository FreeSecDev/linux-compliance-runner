"""Fail when an npm install could resolve anything that the lockfile does not pin.

``make lint-renovate`` installs Renovate from ``tools/renovate/package.json`` and
``tools/renovate/package-lock.json`` with ``npm ci --ignore-scripts``. This
check runs before and after that install and fails when:

* the manifest has a key outside :data:`MANIFEST_KEYS` (for example
  ``overrides``, ``scripts`` or another dependency type), is not private, has no
  exact ``packageManager`` pin, or declares a dependency that is not an exact
  ``MAJOR.MINOR.PATCH`` version (a range, tag, URL, git or file reference);
* the lockfile is not ``lockfileVersion`` 3, belongs to another project, or its
  root entry does not declare exactly the manifest's dependencies;
* a locked package is linked, has a malformed path or version, is not resolved
  to its own tarball on :data:`REGISTRY` (``<name>/-/<base>-<version>.tgz``),
  or lacks a single SHA-512 ``integrity`` hash; bundled packages ship inside
  the integrity-checked tarball of their parent and need neither;
* a dependency, optional dependency or required peer dependency of any locked
  package (or of the root) does not resolve to a locked package through the
  ``node_modules`` lookup that npm uses, so npm would have to resolve it;
* with ``--installed``, the tree that npm wrote to
  ``node_modules/.package-lock.json`` differs from the committed lockfile: an
  installed package that is not locked or has another version, tarball or
  hash, or a locked non-optional package that was not installed.

Violations are printed one per line. Exit status: 0 when every check passes,
1 on a violation, 2 for usage errors.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence

DESCRIPTION: Final[str] = "Fail when an npm install could resolve an unpinned package."
REGISTRY: Final[str] = "https://registry.npmjs.org/"
LOCKFILE_VERSION: Final[int] = 3
MANIFEST_KEYS: Final[frozenset[str]] = frozenset(
    {"name", "private", "description", "license", "packageManager", "dependencies"}
)
REQUIRED_MANIFEST_KEYS: Final[tuple[str, ...]] = (
    "name",
    "private",
    "packageManager",
    "dependencies",
)
ROOT_KEYS: Final[frozenset[str]] = frozenset({"name", "version", "license", "dependencies"})
EDGE_KINDS: Final[tuple[str, ...]] = ("dependencies", "optionalDependencies", "peerDependencies")
INSTALLED_FIELDS: Final[tuple[str, ...]] = ("version", "resolved", "integrity")
EXACT_VERSION: Final[re.Pattern[str]] = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}")
LOCKED_VERSION: Final[re.Pattern[str]] = re.compile(
    r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)
PACKAGE_MANAGER: Final[re.Pattern[str]] = re.compile(
    r"npm@(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}"
)
PACKAGE_NAME: Final[str] = r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*"
NAME: Final[re.Pattern[str]] = re.compile(PACKAGE_NAME)
LOCK_PATH: Final[re.Pattern[str]] = re.compile(
    rf"node_modules/{PACKAGE_NAME}(?:/node_modules/{PACKAGE_NAME})*"
)
INTEGRITY: Final[re.Pattern[str]] = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")
SEGMENT: Final[str] = "node_modules/"


class LockInputError(ValueError):
    """A manifest or lockfile cannot be read as a JSON object."""


def _object(value: object) -> dict[str, object] | None:
    """Return ``value`` as a string-keyed mapping, or ``None`` when it is not an object."""
    return cast("dict[str, object]", value) if isinstance(value, dict) else None


def load_json(path: Path) -> dict[str, object]:
    """Read ``path`` as a JSON object."""
    try:
        document: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        message = f"{path}: cannot read JSON: {error}"
        raise LockInputError(message) from error
    result = _object(document)
    if result is None:
        message = f"{path}: the top level is not a JSON object"
        raise LockInputError(message)
    return result


def check_manifest(manifest: Mapping[str, object]) -> list[str]:
    """Return every reason why ``manifest`` does not pin its dependencies exactly."""
    violations = [
        f"package.json: key {key!r} is not allowed" for key in sorted(set(manifest) - MANIFEST_KEYS)
    ]
    violations.extend(
        f"package.json: key {key!r} is required"
        for key in REQUIRED_MANIFEST_KEYS
        if key not in manifest
    )
    if "private" in manifest and manifest["private"] is not True:
        violations.append("package.json: private must be true")
    manager = manifest.get("packageManager")
    if "packageManager" in manifest and not (
        isinstance(manager, str) and PACKAGE_MANAGER.fullmatch(manager)
    ):
        violations.append(f"package.json: packageManager must be npm@<x.y.z>, got {manager!r}")
    if "dependencies" not in manifest:
        return violations
    dependencies = _object(manifest["dependencies"])
    if not dependencies:
        violations.append("package.json: dependencies must be a non-empty object")
        return violations
    for name, spec in sorted(dependencies.items()):
        if not NAME.fullmatch(name):
            violations.append(f"package.json: dependency name {name!r} is malformed")
        if not (isinstance(spec, str) and EXACT_VERSION.fullmatch(spec)):
            violations.append(
                f"package.json: dependency {name!r} must be an exact x.y.z version, got {spec!r}"
            )
    return violations


def package_name(path: str, entry: Mapping[str, object]) -> str:
    """Return the registry name of the package installed at ``path``."""
    alias = entry.get("name")
    return alias if isinstance(alias, str) else path.rpartition(SEGMENT)[2]


def tarball_url(name: str, version: str) -> str:
    """Return the registry tarball URL of ``name`` at ``version``."""
    return f"{REGISTRY}{name}/-/{name.rpartition('/')[2]}-{version}.tgz"


def check_entry(path: str, entry: Mapping[str, object]) -> list[str]:
    """Return every pinning problem of the locked package at ``path``."""
    where = f"package-lock.json: {path}"
    if not LOCK_PATH.fullmatch(path):
        return [f"{where}: malformed package path"]
    violations: list[str] = []
    if "link" in entry:
        violations.append(f"{where}: linked packages are not allowed")
    version = entry.get("version")
    if not (isinstance(version, str) and LOCKED_VERSION.fullmatch(version)):
        violations.append(f"{where}: version must be an exact semantic version, got {version!r}")
        return violations
    if entry.get("inBundle") is True:
        return violations
    name = package_name(path, entry)
    expected = tarball_url(name, version) if NAME.fullmatch(name) else None
    resolved = entry.get("resolved")
    if expected is None or resolved != expected:
        violations.append(f"{where}: resolved must be {expected!r}, got {resolved!r}")
    integrity = entry.get("integrity")
    if not (isinstance(integrity, str) and INTEGRITY.fullmatch(integrity)):
        violations.append(f"{where}: integrity must be one sha512 hash, got {integrity!r}")
    return violations


def lookup_candidates(path: str, name: str) -> Iterator[str]:
    """Yield the lockfile paths where npm looks for ``name`` required from ``path``."""
    base = path
    while base:
        yield f"{base}/{SEGMENT}{name}"
        base = base.rpartition(f"/{SEGMENT}")[0]
    yield f"{SEGMENT}{name}"


def _edges(entry: Mapping[str, object]) -> Iterator[str]:
    """Yield the names that ``entry`` requires to be installed."""
    optional_peers = {
        name
        for name, meta in (_object(entry.get("peerDependenciesMeta")) or {}).items()
        if (_object(meta) or {}).get("optional") is True
    }
    for kind in EDGE_KINDS:
        for name in _object(entry.get(kind)) or {}:
            if kind != "peerDependencies" or name not in optional_peers:
                yield name


def _unresolved_edges(path: str, entry: Mapping[str, object], locked: set[str]) -> list[str]:
    """Return the requirements of ``path`` that no locked package satisfies."""
    shown = path or "<root>"
    return [
        f"package-lock.json: {shown} requires {name!r}, which is not in the lockfile"
        for name in _edges(entry)
        if not any(candidate in locked for candidate in lookup_candidates(path, name))
    ]


def check_lockfile(manifest: Mapping[str, object], lock: Mapping[str, object]) -> list[str]:
    """Return every way in which ``lock`` leaves a package of ``manifest`` unpinned."""
    violations: list[str] = []
    version = lock.get("lockfileVersion")
    if not (isinstance(version, int) and version == LOCKFILE_VERSION):
        violations.append(f"package-lock.json: lockfileVersion must be 3, got {version!r}")
    if lock.get("name") != manifest.get("name"):
        violations.append("package-lock.json: name differs from package.json")
    if lock.get("requires") is not True:
        violations.append("package-lock.json: requires must be true")
    packages = _object(lock.get("packages"))
    if packages is None:
        violations.append("package-lock.json: packages must be an object")
        return violations
    root = _object(packages.get(""))
    if root is None:
        violations.append("package-lock.json: the root package entry is missing")
        return violations
    violations.extend(
        f"package-lock.json: root key {key!r} is not allowed"
        for key in sorted(set(root) - ROOT_KEYS)
    )
    if root.get("dependencies") != manifest.get("dependencies"):
        violations.append("package-lock.json: root dependencies differ from package.json")
    locked = {path for path in packages if path}
    for path, value in sorted(packages.items()):
        entry = _object(value)
        if entry is None:
            violations.append(f"package-lock.json: {path or '<root>'} is not an object")
            continue
        if path:
            violations.extend(check_entry(path, entry))
        violations.extend(_unresolved_edges(path, entry, locked))
    return violations


def check_installed(lock: Mapping[str, object], installed: Mapping[str, object]) -> list[str]:
    """Return every difference between the installed tree and the committed lockfile."""
    locked = _object(lock.get("packages")) or {}
    present = _object(installed.get("packages"))
    if present is None:
        return ["installed tree: packages must be an object"]
    violations: list[str] = []
    for path, value in sorted(present.items()):
        expected = _object(locked.get(path)) if path else None
        entry = _object(value) or {}
        if expected is None:
            violations.append(f"installed tree: {path or '<root>'} is not in the lockfile")
            continue
        violations.extend(
            f"installed tree: {path} {field} is {entry.get(field)!r}, "
            f"locked {expected.get(field)!r}"
            for field in INSTALLED_FIELDS
            if entry.get(field) != expected.get(field)
        )
    violations.extend(
        f"installed tree: locked package {path} was not installed"
        for path, value in sorted(locked.items())
        if path and path not in present and (_object(value) or {}).get("optional") is not True
    )
    return violations


def run(manifest_path: Path, lock_path: Path, installed_path: Path | None) -> list[str]:
    """Run every check and return the violations."""
    try:
        manifest = load_json(manifest_path)
        lock = load_json(lock_path)
        installed = load_json(installed_path) if installed_path is not None else None
    except LockInputError as error:
        return [str(error)]
    violations = [*check_manifest(manifest), *check_lockfile(manifest, lock)]
    if installed is not None:
        violations.extend(check_installed(lock, installed))
    return violations


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser."""
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--manifest", type=Path, required=True, help="package.json to check.")
    parser.add_argument("--lockfile", type=Path, required=True, help="package-lock.json to check.")
    parser.add_argument(
        "--installed",
        type=Path,
        help="node_modules/.package-lock.json written by npm ci, compared with the lockfile.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    arguments = build_parser().parse_args(argv)
    violations = run(arguments.manifest, arguments.lockfile, arguments.installed)
    for violation in violations:
        print(violation)
    if violations:
        return 1
    scope = "lockfile and installed tree" if arguments.installed else "lockfile"
    print(f"npm lock check passed: every package is pinned by the {scope}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
