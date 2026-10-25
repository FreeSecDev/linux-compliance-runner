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
| CPython | 3.12.13 | uv managed distribution | Manual pull request (`PYTHON_VERSION` in the Containerfile) |
| uv | 0.11.19 | Alpine package | Manual (Renovate extraction of `apk` pins is not available) |
| OpenTofu | 1.13.1 | GitHub release, SHA-256 verified | Renovate (`custom.regex`, version and checksum together) |
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

Pin ages: Python packages, OpenTofu and the pins above were at least seven days old when chosen. `toolbox/pyproject.toml`
sets `exclude-newer = "7 days"`, so every `uv lock` enforces the rule. Security fixes are exempt: `certifi` is excluded from
that window, and the constraints copied from the collection (`packaging`, `asteval`, `virtualenv`) are security floors.
OpenTofu 1.13.1 is one patch behind the collection's installer script (1.13.2) for the same reason.

### Dependency ownership

- Dependabot (`uv`) owns `toolbox/pyproject.toml` and `toolbox/uv.lock`, in `.github/dependabot.yml`. A Dependabot pull request
  changes only the lock; the Containerfile exports it during the build, so nothing else needs regenerating.
- Renovate owns the base image digest (built-in `dockerfile` manager) and the OpenTofu version and checksum (`customManagers`
  in `.renovaterc.json`, datasource `github-release-attachments`, which also computes the new archive digest).
  Validate with `npx --package renovate renovate-config-validator --strict --no-global`.
- `apk` pins are not updated by any bot yet (planned). Renovate's `dockerfile` manager reads `apk add name=version` pins
  but, in the version tested (44.181.5), marks them skipped at extraction with `unknown-registry`, so no custom manager can
  revive them from configuration alone. Bump them by hand when a build reports a missing package version.
- The managed Python version is changed only by a deliberate pull request, as for the rest of the platform.

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
- OpenTofu verified against a pinned SHA-256 before extraction; the build fails on non-amd64 builders.
- User `toolbox`, UID and GID 10001, `WORKDIR /work`. No `ENTRYPOINT`, no exposed ports.
- No SSH daemon (the OpenSSH client only). setuid and setgid bits are stripped from every file in the image.
- Installed trees under `/opt` are root-owned and not writable by the runtime user.
- Works with `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges` and `--network=none`.
  `HOME` is `/home/toolbox`; uv, pre-commit, XDG and Ansible caches point into `/tmp`. Mount tmpfs (or volumes) at `/tmp` and
  `/home/toolbox`, and the checkout at `/work`.
- No credentials, build secrets or tokens. The OCI labels carry source, licence, version and revision only.
- OCI labels: title, description, source, url, documentation, licenses, vendor, base name, version, revision, created.
  `version`, `revision` and `created` default to `0.0.0-dev`, `unknown`, `unknown` and are set with `--build-arg`
  (`IMAGE_VERSION`, `VCS_REF`, `BUILD_DATE`); `make image-smoke` sets the revision.

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

The test build measured with Docker 29 on 2026-10-25: about 277 MB as stored by the engine and about 940 MB uncompressed
(the Python environment is roughly 590 MB, mostly Checkov and its dependencies; OpenTofu 114 MB; CPython 90 MB; Alpine packages 144 MB).

## Known limits

- linux/amd64 only.
- Transitive `apk` dependencies are not individually pinned; they come from the pinned Alpine release and are covered by the
  SBOM and scan (FREES-37).
- Scanning, SBOM, signing and publication belong to FREES-36 and FREES-37.
