# Toolbox image

Scope: what the CI toolbox image contains, how it is pinned and who updates each pin, its security properties, and how to
test it. Design rationale is in [ADR 0001](adr/0001-toolbox-image.md). Jira: FREES-35 (Containerfile), FREES-38 (smoke tests).

The image is a job toolbox for the `freesecdev.linux_compliance` CI. It is not a self-hosted runner: it has no runner agent,
no entrypoint and no network service. The release image is built in AWS (FREES-36), scanned, signed and consumed by digest.
The local and CI builds described here are test builds only. They are tagged `localhost/linux-compliance-runner:smoke` and are never pushed.

## Contents

| Tool | Version | Source | Pin owner |
|---|---|---|---|
| Alpine Linux | 3.24, index digest `sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a` | Docker Official Image | Renovate (`dockerfile`) |
| CPython | 3.12.15 | python-build-standalone `20261013`, musl `install_only_stripped`, SHA-256 verified; pip, ensurepip, IDLE and the test suite removed | Renovate (`custom.regex` on the release tag and checksum); the Python minor version changes only by a deliberate pull request |
| uv | 0.11.19 | Alpine package | Manual (Renovate extraction of `apk` pins is not available) |
| OpenTofu | 1.13.2 | GitHub release, SHA-256 verified | Renovate (`custom.regex`, version and checksum together) |
| ansible-core (`ansible`, `ansible-galaxy`) | 2.21.5 | PyPI, hash-locked | Dependabot (`uv`, `/toolbox`) |
| ansible-lint | 26.10.1 | PyPI, hash-locked | Dependabot |
| Molecule | 26.10.0 | PyPI, hash-locked | Dependabot |
| antsibull-changelog | 0.35.2 | PyPI, hash-locked | Dependabot |
| pytest, coverage, pytest-cov, PyYAML, types-PyYAML | see `toolbox/uv.lock` | PyPI, hash-locked | Dependabot |
| Ruff, mypy, Pyright, Pylint, Bandit, yamllint | see `toolbox/uv.lock` | PyPI, hash-locked | Dependabot |
| zizmor | 1.31.1 | PyPI, hash-locked | Dependabot |
| Checkov | 3.3.29 | PyPI, hash-locked | Dependabot |
| hadolint | 2.15.1 | `hadolint-bin` wheel, hash-locked | Dependabot |
| actionlint | 1.7.12 | Alpine package | Manual |
| ShellCheck | 0.11.0 | Alpine package | Manual |
| Node.js (runs Pyright) | 24.22.1 | Alpine package | Manual |
| git, OpenSSH client, jq, GNU make, bash, ca-certificates | pinned in the Containerfile | Alpine packages | Manual |

The exact Python versions are the ones in `toolbox/uv.lock`; the smoke tests compare every tool's reported version with that
lock, the Containerfile `apk` pins and the `ARG` values.

Pin ages: Python packages and the pins above were at least seven days old when chosen. Security fixes are exempt: OpenTofu
1.13.2 and CPython 3.12.15 are security releases, and `certifi` and the constraints copied from the collection
(`packaging`, `asteval`, `virtualenv`) are security floors with their reasons in `toolbox/pyproject.toml`. As in the
collection, `exclude-newer` is not used: it would block Dependabot security updates for fresh releases.
The image ships Alpine's uv 0.11.19 while CI uses uv 0.13.1; uv only exports the lock and installs wheels inside the build.

### Dependency ownership

- Dependabot (`uv`) owns `toolbox/pyproject.toml` and `toolbox/uv.lock`, in `.github/dependabot.yml`. A Dependabot pull request
  changes only the lock; the Containerfile exports it during the build, so nothing else needs regenerating.
- Renovate owns the base image digest (built-in `dockerfile` manager) and the OpenTofu version and checksum (`customManagers`
  in `.renovaterc.json`, datasource `github-release-attachments`, which also computes the new archive digest).
  `make lint-renovate` (part of `make lint`) runs `renovate-config-validator --strict --no-global` with a pinned Renovate
  version; it needs Node.js 24 and fails with a clear message otherwise. The 7-day `minimumReleaseAge` also applies to these
  managers, so a security release of OpenTofu or CPython needs a manual pull request.
- `RENOVATE_VERSION` in the Makefile is tracked by a regex manager on the npm datasource. CI runs the validator on Node.js 24.22.1
  (the 2026-10-20 security release, same as the image). `npx` has no lockfile, so Renovate's transitive packages are not
  pinned; a committed lockfile is tracked separately.
- The python-build-standalone manager tracks the release tag and the archive digest. Its asset name contains the CPython
  patch version, so the upstream `SHA256SUMS` (142 KB) exceeds the datasource's 5120-byte checksum-file limit and Renovate falls back to
  downloading and hashing release assets until one matches (about 109 assets and 2.8 GB per lookup). When a newer release no longer carries 3.12.15 the bot cannot compute a digest and a maintainer updates
  `PYTHON_VERSION` and the checksum by hand from the release `SHA256SUMS`.
- `apk` pins are not updated by any bot yet (planned). Renovate's `dockerfile` manager reads `apk add name=version` pins
  but, in the version tested (44.167.5), marks them skipped at extraction with `unknown-registry`, so no custom manager can
  revive them from configuration alone. Bump them by hand when a build reports a missing package version.

Bump the OpenTofu checksum from the project's `tofu_<version>_SHA256SUMS` (linux_amd64 line) and compare it with the signed release.
Regenerate the Python lock with:

```text
uv lock --directory toolbox
make lint-container
```

## Security properties

- Multi-stage build; the final stage has no compilers, package caches, `curl` or build tooling.
- Base image pinned by digest; `apk add` with exact versions; no `apk upgrade`.
- Python tools installed with `--require-hashes --only-binary :all:` from the locked export.
- OpenTofu and CPython are verified against pinned SHA-256 values before extraction; the build fails on non-amd64 builders.
- User `toolbox`, UID and GID 10001, `WORKDIR /work`. No `ENTRYPOINT`, no exposed ports.
- No SSH daemon (the OpenSSH client only). setuid and setgid bits are stripped from every file in the image.
- Installed trees under `/opt` are root-owned and not writable by the runtime user.
- Works with `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges` and `--network=none`.
  `HOME` is `/home/toolbox`; uv, pre-commit, XDG and Ansible caches point into `/tmp`. Mount tmpfs (or volumes) at `/tmp` and
  `/home/toolbox`, and the checkout at `/work`.
- No credentials, build secrets or tokens. The OCI labels carry source, licence, version and revision only.
- OCI labels: title, description, source, url, documentation, licenses, vendor, base name, version, revision, created.
  `version` and `revision` default to `0.0.0-dev` and `unknown`; `BUILD_DATE` (RFC 3339) has no default and the build fails
  without it. They are set with `--build-arg` (`IMAGE_VERSION`, `VCS_REF`, `BUILD_DATE`); `make image-smoke` sets the revision
  and derives the date from `SOURCE_DATE_EPOCH` (default: the commit time).

## Variants

There is one variant today: the `toolbox` target. `runtime-base` holds the user, packages and permissions; a future `report`
target (collection ADR 0012) starts from it instead of copying the file.

## Smoke tests

```text
make lint-container
make image-smoke
```

`make image-smoke` needs `docker` (or `podman`) and `uv`. It builds the image with the Containerfile, tags it
`localhost/linux-compliance-runner:smoke` (local only) and runs `tests/smoke/test_image.py` with:

```text
--read-only --cap-drop=ALL --security-opt=no-new-privileges --user 10001 --network=none --tmpfs /tmp
```

plus a tmpfs on `/home/toolbox` owned by 10001. The tests assert that each bundled tool reports its pinned version, the effective
identity is `toolbox` 10001:10001, no setuid or setgid file and no `sshd` exist (scanned as root so every directory is
visible), the root file system is read-only while `HOME` and the caches are writable on tmpfs, no credentials appear in the
environment or file system, the OCI labels and image user are set, Ruff, Pyright and `tofu fmt` run offline, and
`ansible-galaxy collection build` succeeds on the sample collection in `tests/smoke/sample_collection/`.
Without `SMOKE_IMAGE` set the tests are skipped, so `pytest` alone never needs a container engine.

The `container` job in `.github/workflows/ci.yml` runs `make lint-container` and `make image-smoke` on a GitHub-hosted runner with
`contents: read` only. It is a test build of the Containerfile, not a release artifact: nothing is pushed, signed or attested.

## Image size

The test build measured with Docker 29 on 2026-10-25: about 267 MB as stored by the engine and about 893 MB uncompressed
(the Python environment is roughly 564 MB, mostly Checkov and its dependencies; OpenTofu 114 MB; CPython 72 MB; Alpine packages 144 MB).

## Vulnerability exceptions

[`security/vulnerability-exceptions.yaml`](../security/vulnerability-exceptions.yaml) is the machine-readable list a later Grype
gate (FREES-37) consumes. Each entry has the ID, component, severity, justification, owner, Jira issue, creation date and an
expiry no later than 90 days out; a unit test fails when an entry is incomplete, too long-lived or expired.
Grype 0.120.1 (checksum verified, database built 2026-10-25) on the test build reports no fixable critical or high finding
except these, none of which can be fixed in this repository yet:

| ID | Component | Severity | Why accepted | Expires |
|---|---|---|---|---|
| GO-2026-6612 | `golang.org/x/net` v0.57.0 inside OpenTofu 1.13.2 (fixed in 0.60.0) | critical | No OpenTofu release includes the fix; the toolbox runs tofu as a short-lived client only | 2027-01-23 |
| GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6617 | same module | high | same | 2027-01-23 |
| GHSA-2v4p-qf9q-27wj | `google.golang.org/grpc` v1.83.1 inside OpenTofu 1.13.2 (fixed in 1.83.2) | high | same | 2027-01-23 |
| GHSA-wj6h-64fc-37mp | `ecdsa` 0.19.2, transitive of Checkov | high | No fixed release exists; Checkov uses only signature verification, the attack targets signing; mirrors the collection's entry | 2027-01-23 |

Owner: lead architect (OpenTofu entries, FREES-37) and project owner (`ecdsa`, FREES-82). Re-check whenever a new OpenTofu
release appears and re-run the OSV query over `toolbox/uv.lock` before the expiry.

## Known limits

- linux/amd64 only.
- Transitive `apk` dependencies are not individually pinned; they come from the pinned Alpine release and are covered by the
  SBOM and scan (FREES-37).
- Scanning, SBOM, signing and publication belong to FREES-36 and FREES-37.
