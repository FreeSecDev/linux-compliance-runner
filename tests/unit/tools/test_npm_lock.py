from __future__ import annotations

import json
import re
import runpy
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Final, cast

import pytest

from tools.security import npm_lock

ROOT: Final[Path] = Path(__file__).resolve().parents[3]
PROJECT: Final[Path] = ROOT / "tools" / "renovate"
MAKEFILE: Final[Path] = ROOT / "Makefile"
HASH: Final[str] = "sha512-" + "A" * 86 + "=="
OTHER_HASH: Final[str] = "sha512-" + "B" * 86 + "=="
DELETE: Final[object] = object()


def locked(package: str, version: str, **extra: Any) -> dict[str, Any]:
    return {
        "version": version,
        "resolved": npm_lock.tarball_url(package, version),
        "integrity": HASH,
        **extra,
    }


def manifest() -> dict[str, Any]:
    return {
        "name": "validator",
        "private": True,
        "description": "test",
        "license": "Apache-2.0",
        "packageManager": "npm@11.19.1",
        "dependencies": {"tool": "1.2.3"},
    }


def lockfile() -> dict[str, Any]:
    return {
        "name": "validator",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "validator", "license": "Apache-2.0", "dependencies": {"tool": "1.2.3"}},
            "node_modules/tool": locked(
                "tool",
                "1.2.3",
                dependencies={"@scope/lib": "^2.0.0", "nested": "^1.0.0"},
                optionalDependencies={"native": "^3.0.0"},
                peerDependencies={"peer": "*", "maybe": "*"},
                peerDependenciesMeta={"maybe": {"optional": True}},
            ),
            "node_modules/@scope/lib": locked("@scope/lib", "2.0.0-rc.1"),
            "node_modules/tool/node_modules/nested": locked(
                "nested", "1.0.0", dependencies={"@scope/lib": "^2.0.0", "deep": "1.0.0"}
            ),
            "node_modules/tool/node_modules/nested/node_modules/deep": locked("deep", "1.0.0"),
            "node_modules/native": locked("native", "3.0.0", optional=True),
            "node_modules/peer": locked("peer", "4.0.0"),
            "node_modules/alias-cjs": locked("real-name", "5.0.0", name="real-name"),
        },
    }


def installed_tree(lock: dict[str, Any] | None = None) -> dict[str, Any]:
    packages = deepcopy((lock or lockfile())["packages"])
    del packages[""]
    return {"name": "validator", "lockfileVersion": 3, "requires": True, "packages": packages}


def set_path(document: dict[str, Any], path: tuple[str, ...], value: object) -> None:
    node: Any = document
    for step in path[:-1]:
        node = node[step]
    if value is DELETE:
        del node[path[-1]]
    else:
        node[path[-1]] = value


def test_valid_inputs_pass() -> None:
    assert npm_lock.check_manifest(manifest()) == []
    assert npm_lock.check_lockfile(manifest(), lockfile()) == []
    assert npm_lock.check_installed(lockfile(), installed_tree()) == []


def test_committed_renovate_tree_is_fully_pinned() -> None:
    package = npm_lock.load_json(PROJECT / "package.json")
    lock = npm_lock.load_json(PROJECT / "package-lock.json")
    assert npm_lock.check_manifest(package) == []
    assert npm_lock.check_lockfile(package, lock) == []
    assert list(cast("dict[str, str]", package["dependencies"])) == ["renovate"]


def test_committed_lockfile_stays_under_the_pre_commit_size_limit() -> None:
    assert (PROJECT / "package-lock.json").stat().st_size < 512 * 1024


def test_committed_npmrc_keeps_the_release_age_and_disables_scripts() -> None:
    settings = (PROJECT / ".npmrc").read_text(encoding="utf-8").splitlines()
    assert "min-release-age=7" in settings
    assert "ignore-scripts=true" in settings


def recipe(target: str) -> str:
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(target)}:.*\n((?:\t.*\n)+)", text, re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_lint_renovate_installs_only_from_the_lockfile() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    body = recipe("lint-renovate")
    assert "npx" not in text
    assert "npm install" not in text
    assert re.search(r"^NPM_CI := npm ci --ignore-scripts ", text, re.MULTILINE)
    for source in ("git", "remote", "file", "directory"):
        assert f"--allow-{source}=none" in text
    steps = [
        "$(NPM_LOCK_CHECK)\n",
        "cd $(RENOVATE_DIR) && $(NPM_CI)\n",
        "$(NPM_LOCK_CHECK) --installed $(RENOVATE_DIR)/node_modules/.package-lock.json\n",
        "$(RENOVATE_VALIDATOR) --strict --no-global .renovaterc.json\n",
    ]
    positions = [body.index(step) for step in steps]
    assert positions == sorted(positions)


def test_grype_checksums_are_verified_with_an_identity_constraint() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    body = recipe("$(GRYPE)")
    identity = (
        r"^GRYPE_SIGNER_IDENTITY := \^https://github\\\.com/anchore/grype/\\\.github/workflows/"
        r"release\\\.yaml@refs/heads/main\$\$$"
    )
    assert re.search(identity, text, re.MULTILINE)
    assert re.search(
        r"^SIGSTORE_OIDC_ISSUER := https://token\.actions\.githubusercontent\.com$",
        text,
        re.MULTILINE,
    )
    assert re.search(r"^COSIGN_SHA256_LINUX_AMD64 := [0-9a-f]{64}$", text, re.MULTILINE)
    for line in (
        "GRYPE_SIGNER_REPOSITORY := anchore/grype",
        "GRYPE_SIGNER_TRIGGER := workflow_dispatch",
        "GRYPE_SIGNER_REF := refs/heads/main",
    ):
        assert re.search(rf"^{re.escape(line)}$", text, re.MULTILINE)
    steps = [
        "$(COSIGN_RUN) verify-blob",
        "--certificate-identity-regexp '$(GRYPE_SIGNER_IDENTITY)'",
        "--certificate-oidc-issuer '$(SIGSTORE_OIDC_ISSUER)'",
        "--certificate-github-workflow-repository '$(GRYPE_SIGNER_REPOSITORY)'",
        "--certificate-github-workflow-trigger '$(GRYPE_SIGNER_TRIGGER)'",
        "--certificate-github-workflow-ref '$(GRYPE_SIGNER_REF)'",
        "grep -Fqx '$(GRYPE_SHA256_LINUX_AMD64)  $(GRYPE_ARCHIVE)'",
        "$(GRYPE_RELEASE_URL)/$(GRYPE_ARCHIVE)",
    ]
    positions = [body.index(step) for step in steps]
    assert positions == sorted(positions)
    cosign = recipe("$(COSIGN)")
    assert "grep -Fqx '$(COSIGN_SHA256_LINUX_AMD64)  cosign-linux-amd64'" in cosign
    assert "sha256sum --check --strict" in cosign


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("dependencies", "tool"), "^1.2.3", "must be an exact x.y.z version, got '^1.2.3'"),
        (("dependencies", "tool"), "~1.2.3", "must be an exact x.y.z version"),
        (("dependencies", "tool"), "latest", "must be an exact x.y.z version"),
        (("dependencies", "tool"), "1.2", "must be an exact x.y.z version"),
        (("dependencies", "tool"), "01.2.3", "must be an exact x.y.z version"),
        (("dependencies", "tool"), "github:owner/tool", "must be an exact x.y.z version"),
        (("dependencies", "tool"), "file:../tool", "must be an exact x.y.z version"),
        (("dependencies", "tool"), "npm:other@1.2.3", "must be an exact x.y.z version"),
        (("dependencies", "tool"), 1, "must be an exact x.y.z version, got 1"),
        (("dependencies", "../evil"), "1.2.3", "dependency name '../evil' is malformed"),
        (("dependencies",), {}, "dependencies must be a non-empty object"),
        (("dependencies",), ["tool"], "dependencies must be a non-empty object"),
        (("dependencies",), DELETE, "key 'dependencies' is required"),
        (("overrides",), {"tool": "1.2.4"}, "key 'overrides' is not allowed"),
        (("scripts",), {"postinstall": "x"}, "key 'scripts' is not allowed"),
        (("devDependencies",), {"x": "1.0.0"}, "key 'devDependencies' is not allowed"),
        (("optionalDependencies",), {"x": "1.0.0"}, "key 'optionalDependencies' is not allowed"),
        (("private",), False, "private must be true"),
        (("private",), "true", "private must be true"),
        (("private",), DELETE, "key 'private' is required"),
        (("name",), DELETE, "key 'name' is required"),
        (("packageManager",), DELETE, "key 'packageManager' is required"),
        (("packageManager",), "npm@^11", "packageManager must be npm@<x.y.z>"),
        (("packageManager",), "pnpm@9.0.0", "packageManager must be npm@<x.y.z>"),
        (("packageManager",), None, "packageManager must be npm@<x.y.z>, got None"),
    ],
    ids=str,
)
def test_manifest_mutation_fails(path: tuple[str, ...], value: object, message: str) -> None:
    document = manifest()
    set_path(document, path, value)
    violations = npm_lock.check_manifest(document)
    assert any(message in violation for violation in violations), violations


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("lockfileVersion",), 2, "lockfileVersion must be 3, got 2"),
        (("lockfileVersion",), "3", "lockfileVersion must be 3, got '3'"),
        (("lockfileVersion",), 3.0, "lockfileVersion must be 3, got 3.0"),
        (("lockfileVersion",), DELETE, "lockfileVersion must be 3, got None"),
        (("name",), "other", "name differs from package.json"),
        (("requires",), False, "requires must be true"),
        (("packages",), [], "packages must be an object"),
        (("packages", ""), DELETE, "the root package entry is missing"),
        (("packages", "", "devDependencies"), {"x": "1"}, "root key 'devDependencies'"),
        (("packages", "", "dependencies", "tool"), "^1.2.3", "root dependencies differ"),
        (("packages", "node_modules/peer"), "x", "node_modules/peer is not an object"),
        (("packages", "node_modules/../evil"), locked("evil", "1.0.0"), "malformed package path"),
        (("packages", "lib/tool"), locked("tool", "1.0.0"), "lib/tool: malformed package path"),
        (("packages", "node_modules/Upper"), locked("Upper", "1.0.0"), "malformed package path"),
        (("packages", "node_modules/peer", "link"), True, "linked packages are not allowed"),
        (("packages", "node_modules/peer", "version"), "^4.0.0", "version must be an exact"),
        (("packages", "node_modules/peer", "version"), DELETE, "version must be an exact"),
        (
            ("packages", "node_modules/peer", "resolved"),
            "git+ssh://git@github.com/owner/peer.git#abc",
            "resolved must be 'https://registry.npmjs.org/peer/-/peer-4.0.0.tgz'",
        ),
        (
            ("packages", "node_modules/peer", "resolved"),
            "https://registry.example.org/peer/-/peer-4.0.0.tgz",
            "resolved must be",
        ),
        (
            ("packages", "node_modules/peer", "resolved"),
            npm_lock.tarball_url("peer", "4.0.1"),
            "resolved must be",
        ),
        (
            ("packages", "node_modules/peer", "resolved"),
            npm_lock.tarball_url("evil", "4.0.0"),
            "resolved must be",
        ),
        (("packages", "node_modules/peer", "resolved"), DELETE, "got None"),
        (("packages", "node_modules/alias-cjs", "name"), "Bad Name", "resolved must be None"),
        (("packages", "node_modules/peer", "integrity"), DELETE, "integrity must be one sha512"),
        (
            ("packages", "node_modules/peer", "integrity"),
            "sha1-" + "A" * 27 + "=",
            "integrity must be one sha512",
        ),
        (
            ("packages", "node_modules/peer", "integrity"),
            f"{HASH} {OTHER_HASH}",
            "integrity must be one sha512",
        ),
        (
            ("packages", "node_modules/tool/node_modules/nested/node_modules/deep"),
            DELETE,
            "node_modules/tool/node_modules/nested requires 'deep'",
        ),
        (("packages", "node_modules/@scope/lib"), DELETE, "requires '@scope/lib'"),
        (("packages", "node_modules/native"), DELETE, "requires 'native'"),
        (("packages", "node_modules/peer"), DELETE, "node_modules/tool requires 'peer'"),
        (("packages", "node_modules/tool"), DELETE, "<root> requires 'tool'"),
    ],
    ids=str,
)
def test_lockfile_mutation_fails(path: tuple[str, ...], value: object, message: str) -> None:
    lock = lockfile()
    set_path(lock, path, value)
    violations = npm_lock.check_lockfile(manifest(), lock)
    assert any(message in violation for violation in violations), violations


def test_optional_peer_dependency_may_be_absent() -> None:
    lock = lockfile()
    assert "node_modules/maybe" not in lock["packages"]
    assert npm_lock.check_lockfile(manifest(), lock) == []


def test_dependency_is_found_in_an_ancestor_node_modules() -> None:
    lock = lockfile()
    nested = lock["packages"]["node_modules/tool/node_modules/nested"]
    assert "@scope/lib" in nested["dependencies"]
    assert "node_modules/tool/node_modules/nested/node_modules/@scope/lib" not in lock["packages"]
    assert npm_lock.check_lockfile(manifest(), lock) == []


def test_candidates_follow_the_node_lookup_order() -> None:
    assert list(npm_lock.lookup_candidates("node_modules/a/node_modules/b", "c")) == [
        "node_modules/a/node_modules/b/node_modules/c",
        "node_modules/a/node_modules/c",
        "node_modules/c",
    ]
    assert list(npm_lock.lookup_candidates("", "c")) == ["node_modules/c"]


BUNDLED: Final[str] = (
    "bundled packages are not allowed: npm installs them without an integrity check"
)


def test_top_level_package_marked_bundled_without_hashes_fails() -> None:
    lock = lockfile()
    entry = lock["packages"]["node_modules/@scope/lib"]
    entry["inBundle"] = True
    del entry["resolved"]
    del entry["integrity"]
    violations = npm_lock.check_lockfile(manifest(), lock)
    where = "package-lock.json: node_modules/@scope/lib"
    assert violations == [
        f"{where}: {BUNDLED}",
        f"{where}: resolved must be {npm_lock.tarball_url('@scope/lib', '2.0.0-rc.1')!r}, got None",
        f"{where}: integrity must be one sha512 hash, got None",
    ]


def test_nested_bundled_package_listed_by_its_parent_still_fails() -> None:
    lock = lockfile()
    lock["packages"]["node_modules/peer"]["bundleDependencies"] = ["bundled"]
    lock["packages"]["node_modules/peer/node_modules/bundled"] = {
        "version": "0.1.0",
        "inBundle": True,
    }
    violations = npm_lock.check_lockfile(manifest(), lock)
    where = "package-lock.json: node_modules/peer/node_modules/bundled"
    assert f"{where}: {BUNDLED}" in violations
    assert f"{where}: integrity must be one sha512 hash, got None" in violations


@pytest.mark.parametrize("flag", [True, False, "true", None])
def test_any_in_bundle_key_fails_even_with_hashes(flag: object) -> None:
    lock = lockfile()
    lock["packages"]["node_modules/peer"]["inBundle"] = flag
    assert npm_lock.check_lockfile(manifest(), lock) == [
        f"package-lock.json: node_modules/peer: {BUNDLED}"
    ]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("integrity", "integrity must be one sha512 hash, got None"),
        (
            "resolved",
            "resolved must be 'https://registry.npmjs.org/peer/-/peer-4.0.0.tgz', got None",
        ),
        ("link", "linked packages are not allowed"),
    ],
)
def test_every_entry_needs_its_own_pin(change: str, message: str) -> None:
    lock = lockfile()
    entry = lock["packages"]["node_modules/peer"]
    if change == "link":
        entry["link"] = True
    else:
        del entry[change]
    assert npm_lock.check_lockfile(manifest(), lock) == [
        f"package-lock.json: node_modules/peer: {message}"
    ]


def test_invalid_version_still_reports_missing_hashes() -> None:
    entry = {"version": "^4.0.0"}
    where = "package-lock.json: node_modules/peer"
    assert npm_lock.check_entry("node_modules/peer", entry) == [
        f"{where}: version must be an exact semantic version, got '^4.0.0'",
        f"{where}: resolved must be None, got None",
        f"{where}: integrity must be one sha512 hash, got None",
    ]


def test_committed_lockfile_has_no_bundled_or_linked_entries() -> None:
    lock = npm_lock.load_json(PROJECT / "package-lock.json")
    packages = cast("dict[str, dict[str, object]]", lock["packages"])
    assert not [path for path, entry in packages.items() if {"inBundle", "link"} & set(entry)]
    assert all(
        entry.get("integrity") and entry.get("resolved") for path, entry in packages.items() if path
    )


def test_tarball_url_of_a_scoped_package() -> None:
    assert npm_lock.tarball_url("@scope/lib", "2.0.0") == (
        "https://registry.npmjs.org/@scope/lib/-/lib-2.0.0.tgz"
    )


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (
            ("packages", "node_modules/extra"),
            locked("extra", "1.0.0"),
            "installed tree: node_modules/extra is not in the lockfile",
        ),
        (("packages", ""), {"name": "validator"}, "installed tree: <root> is not in the lockfile"),
        (
            ("packages", "node_modules/peer", "integrity"),
            OTHER_HASH,
            "installed tree: node_modules/peer integrity is",
        ),
        (
            ("packages", "node_modules/peer", "version"),
            "4.0.1",
            "installed tree: node_modules/peer version is '4.0.1', locked '4.0.0'",
        ),
        (
            ("packages", "node_modules/peer", "resolved"),
            npm_lock.tarball_url("peer", "4.0.1"),
            "installed tree: node_modules/peer resolved is",
        ),
        (
            ("packages", "node_modules/peer"),
            "x",
            "installed tree: node_modules/peer version is None",
        ),
        (
            ("packages", "node_modules/peer"),
            DELETE,
            "installed tree: locked package node_modules/peer was not installed",
        ),
        (("packages",), [], "installed tree: packages must be an object"),
    ],
    ids=str,
)
def test_installed_tree_mutation_fails(path: tuple[str, ...], value: object, message: str) -> None:
    tree = installed_tree()
    set_path(tree, path, value)
    violations = npm_lock.check_installed(lockfile(), tree)
    assert any(message in violation for violation in violations), violations


def test_optional_locked_package_may_be_skipped_by_the_install() -> None:
    tree = installed_tree()
    del tree["packages"]["node_modules/native"]
    assert npm_lock.check_installed(lockfile(), tree) == []


def write(tmp_path: Path, name: str, document: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"{", "cannot read JSON"),
        (b"\xff\xfe", "cannot read JSON"),
        (b"[]", "the top level is not a JSON object"),
    ],
)
def test_load_json_rejects_unreadable_input(tmp_path: Path, content: bytes, message: str) -> None:
    path = tmp_path / "package.json"
    path.write_bytes(content)
    with pytest.raises(npm_lock.LockInputError, match=message):
        npm_lock.load_json(path)


def test_run_reports_a_missing_file(tmp_path: Path) -> None:
    violations = npm_lock.run(tmp_path / "missing.json", tmp_path / "lock.json", None)
    assert len(violations) == 1
    assert "cannot read JSON" in violations[0]


def test_main_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    package = write(tmp_path, "package.json", manifest())
    lock = write(tmp_path, "package-lock.json", lockfile())
    assert npm_lock.main(["--manifest", str(package), "--lockfile", str(lock)]) == 0
    assert "pinned by the lockfile\n" in capsys.readouterr().out


def test_main_passes_with_the_installed_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    package = write(tmp_path, "package.json", manifest())
    lock = write(tmp_path, "package-lock.json", lockfile())
    tree = write(tmp_path, ".package-lock.json", installed_tree())
    arguments = ["--manifest", str(package), "--lockfile", str(lock), "--installed", str(tree)]
    assert npm_lock.main(arguments) == 0
    assert "pinned by the lockfile and installed tree" in capsys.readouterr().out


def test_main_fails_on_a_violation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    document = manifest()
    document["dependencies"]["tool"] = "^1.2.3"
    package = write(tmp_path, "package.json", document)
    lock = write(tmp_path, "package-lock.json", lockfile())
    tree = installed_tree()
    tree["packages"]["node_modules/extra"] = locked("extra", "1.0.0")
    installed = write(tmp_path, ".package-lock.json", tree)
    arguments = ["--manifest", str(package), "--lockfile", str(lock), "--installed", str(installed)]
    assert npm_lock.main(arguments) == 1
    out = capsys.readouterr().out
    assert "must be an exact x.y.z version" in out
    assert "node_modules/extra is not in the lockfile" in out
    assert "passed" not in out


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    package = write(tmp_path, "package.json", manifest())
    lock = write(tmp_path, "package-lock.json", {**lockfile(), "lockfileVersion": 2})
    monkeypatch.setattr(
        sys, "argv", ["npm_lock", "--manifest", str(package), "--lockfile", str(lock)]
    )
    monkeypatch.delitem(sys.modules, "tools.security.npm_lock", raising=False)
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("tools.security.npm_lock", run_name="__main__")
    assert caught.value.code == 1
