# 0001. CI toolbox image design

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** FREES-35 (Containerfile), FREES-38 (smoke tests)
- **Pull requests:** pending
- **Related:** collection repository [0006](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0006-toolchain-selection.md), [0007](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0007-registry-build-and-signing.md), [0012](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0012-github-native-releases-and-packages.md)

## Context

The collection repository runs its CI inside one image that carries every tool it needs, consumed by digest.
Collection ADR 0007 decides that the release image is built in AWS and published to GHCR, and collection ADR 0006
decides which security tools the platform uses and that every tool is installed by pinned version and checksum.
This repository must define the image itself: base, package and tool installation, runtime posture and how it is tested.
The image is a job toolbox, not a self-hosted runner service.

## Decision

- **Build file:** one `Containerfile` with named stages. `toolbox` is the last, and therefore default, stage. Future
  variants such as the report image of collection ADR 0012 are further stages that reuse `runtime-base`, not new files.
- **Base:** Alpine 3.24 pinned by the multi-architecture index digest. Renovate's `dockerfile` manager keeps tag and digest current.
- **System packages:** installed with `apk add` using exact `package=version-rN` pins. No `apk upgrade`. Only directly
  requested packages are pinned; their dependencies come from the same Alpine release and are covered by the SBOM and scan.
- **Python:** CPython 3.12 (the collection's version) from python-build-standalone, downloaded in the builder stage and
  verified against a pinned SHA-256, because Alpine 3.24 ships Python 3.14 only and the CPython bundled with Alpine's uv
  lags the security releases. pip, ensurepip, IDLE and the test suite are removed.
  Tools install from `toolbox/pyproject.toml` and `toolbox/uv.lock`, exported inside the build with `uv export --frozen` and
  installed with `--require-hashes --only-binary :all: --no-deps`, so no sdist is built and every file is hash-checked.
  Dependabot owns this lock. The same `override-dependencies` and `constraint-dependencies` security fixes as the collection apply.
- **Non-Python binaries:** OpenTofu is downloaded in a throwaway builder stage from its GitHub release, pinned to a
  version and the SHA-256 of the linux/amd64 archive, and verified before extraction. actionlint and shellcheck come from
  Alpine because `actionlint-py` is source-only (its build downloads an unverified binary) and the Alpine packages are
  built from source by the distribution. hadolint comes from the `hadolint-bin` wheel.
- **Runtime posture:** non-root user `toolbox` (UID and GID 10001), `WORKDIR /work`, no `ENTRYPOINT`, no SSH daemon
  (only the OpenSSH client), setuid and setgid bits stripped from every file, no credentials, caches and `HOME` redirected
  to paths that a tmpfs can back, so the root file system can be read-only and all capabilities dropped.
- **Architecture:** linux/amd64 only for now. The OpenTofu checksum is amd64 only, and the build fails on other architectures
  instead of installing an unverified binary.
- **Tests:** `tests/smoke/` runs the built image with `--read-only --cap-drop=ALL --security-opt=no-new-privileges
  --user 10001 --network=none` and tmpfs mounts, through `make image-smoke`. A `container` CI job runs it on a
  GitHub-hosted runner as a test build. That image is never pushed and is not a release artifact; release images are built
  only in AWS (collection ADR 0007, FREES-36).
- **Lint:** hadolint with `failure-threshold: style` and no ignores, plus a check that `toolbox/uv.lock` matches its `pyproject.toml`.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Alpine's own `python3` | Alpine 3.24 provides 3.14; the collection targets 3.12 |
| Debian slim base | Larger attack surface and size; Alpine is the repository standard |
| `actionlint-py` from PyPI | Source distribution only; its build fetches a binary with no hash check |
| Committed `requirements.txt` next to `uv.lock` | Dependabot updates `uv.lock` only, so the two files would drift |
| Alpine `opentofu` package | The collection pins a specific OpenTofu release with a verified checksum; the package version cannot be chosen independently |
| Separate Containerfile per variant | Duplicates the build definition; stages share it |

## Benefits

Reproducible, hash-verified Python and binary installs; a small runtime surface; one build definition for all variants;
a test that fails if the image drifts from its pins.

## Trade-offs

Alpine drops superseded package revisions from its index, so an `apk` pin can stop resolving and the build then fails
until the pin is bumped. This is intentional (fail closed) and is the cost of exact pins. Renovate cannot update `apk`
pins yet (see below), so they are bumped by hand. `--no-deps` relies on the lock being a complete closure, and
`uv pip check` is not used because the lock deliberately overrides Checkov's stale pins (`packaging`, `asteval`).
The image is large (about 890 MB uncompressed) because Checkov, ansible-lint and Molecule bring many dependencies.

## Security implications

- No secrets exist at build or run time; the build uses no build secrets and the smoke tests assert that the environment and
  file system contain no credential files.
- The OpenTofu checksum is taken from the project's own release, so it detects corruption and tampering of the download but
  not a compromised release; reviewers compare it with the signed `SHA256SUMS` when bumping.
- OpenTofu 1.13.2 and CPython 3.12.15 are security releases and exempt from the seven day pin age rule. Remaining OpenTofu
  findings (`x/net`, `grpc`) and `ecdsa` are recorded as expiring exceptions in `security/vulnerability-exceptions.yaml`.
- Python files executed from `/opt` are root-owned and read-only to the runtime user.
- The pyright wheel bundles its JavaScript, so no network or npm install happens at build or run time; the Node.js runtime is the Alpine package.

## Operational consequences

- Renovate (`dockerfile` manager) updates the base digest. A regex custom manager updates the OpenTofu version together
  with its checksum through the `github-release-attachments` datasource; a second one does the same for the
  python-build-standalone release. `apk` pins are updated by hand (Renovate's dockerfile manager extracts `apk` pins but always skips them in the version in use).
- Dependabot (`uv`, directory `/toolbox`) owns the Python tool versions and security updates.
- Release builds, scanning, SBOM and signing remain FREES-36 and FREES-37.
