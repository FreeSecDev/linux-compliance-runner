# Toolbox image

Scope: what the CI toolbox image contains, how it is pinned and who updates each pin, its security properties, and how to
test and scan it. Design rationale is in [ADR 0001](adr/0001-toolbox-image.md). Jira: FREES-35 (Containerfile), FREES-38 (smoke tests),
FREES-37 (vulnerability gate).

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
  `version` and `revision` default to `0.0.0-dev` and `unknown`; `BUILD_DATE` has no default, and the build itself fails
  when it is missing or is not a single-line RFC 3339 date-time with an upper-case `T` and a `Z` or `±hh:mm` offset on a real
  calendar day (for example `2026-02-30T00:00:00Z` is rejected). They are set with `--build-arg` (`IMAGE_VERSION`, `VCS_REF`, `BUILD_DATE`); `make image-smoke` sets the revision
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

The smoke tests also build the `toolbox` target with malformed `BUILD_DATE` values (empty, date only, a space instead of `T`,
hour 24, 30 February, no offset, an embedded newline, free text) and expect the build to stop with the `BUILD_DATE` error.

The `container` job in `.github/workflows/ci.yml` runs `make lint-container`, `make image-smoke` and then `make image-scan` on a
GitHub-hosted runner with `contents: read` only. It is a test build of the Containerfile, not a release artifact: nothing is
pushed, signed or attested.

## Image size

The test build measured with Docker 29 on 2026-10-25: about 267 MB as stored by the engine and about 893 MB uncompressed
(the Python environment is roughly 564 MB, mostly Checkov and its dependencies; OpenTofu 114 MB; CPython 72 MB; Alpine packages 144 MB).

## Vulnerability gate

```text
make image-smoke
make image-scan
```

`make image-scan` scans an image that already exists in the local engine (`SCAN_IMAGE`, default the smoke tag, so run
`make image-smoke` first) and fails closed. It needs `docker` or `podman`, `uv`, `curl`, `jq`, `sha256sum` and network access.

1. **Scanner.** Grype `GRYPE_VERSION` (0.121.0, a security release; see
   [`dependency-management.md`](dependency-management.md#grype-version)) is downloaded from the GitHub release into `build/tools/grype-<version>/`.
   The SHA-256 pinned in the Makefile (`GRYPE_SHA256_LINUX_AMD64`) must appear verbatim in the release `checksums.txt` and must
   match the archive; nothing is piped into a shell. The binary must report the pinned version and database schema. linux/amd64
   only. The release also carries a Sigstore bundle for `checksums.txt`; it is not verified yet because the toolchain has no
   cosign, so the committed checksum is the trust anchor. Renovate updates the version and checksum together (see
   [`dependency-management.md`](dependency-management.md)).
2. **Database.** Grype databases are rebuilt daily and are not signed, so a database cannot be pinned in the repository
   without going stale within days. The target pins what Grype allows: the schema major (`GRYPE_DB_SCHEMA`, 6, which must equal
   the schema the binary supports) and the listing URL (`https://grype.anchore.io/databases/v6/latest.json`). It downloads the
   listing, checks that the archive name and the `sha256:` checksum have the expected form, downloads the archive (about
   195 MB) into `build/grype-db/archives/` (reused while it is still the current one), verifies its SHA-256 against the listing
   and imports it with `grype db import`. Scans run with automatic updates disabled, so the scan uses exactly the database that
   was verified.
3. **Database age.** Grype refuses a database older than `GRYPE_DB_MAX_AGE_HOURS` (120 hours) through `validate-age`, and the
   gate checks the build time recorded in the report again: older than 120 hours, or more than five minutes in the future,
   fails the gate, so a stale database cannot produce a false pass.
4. **Configuration and environment.** Grype runs with `--config security/grype.yaml`. Passing a config file stops Grype
   from also reading a `.grype.yaml` from the working or home directory. Every Grype command runs under `env -i`, so no
   inherited `GRYPE_*` variable (for example `GRYPE_MATCH_STOCK_USING_CPES=false`, `GRYPE_DISTRO` or `GRYPE_ONLY_FIXED`) reaches
   it. Only these variables are passed: `PATH`, `HOME`, `TMPDIR`, the container engine connection (`DOCKER_HOST`,
   `DOCKER_CONTEXT`, `DOCKER_CONFIG`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`, and `CONTAINER_HOST` and `XDG_RUNTIME_DIR` for
   podman; an unset one is passed empty, which the clients treat as unset), plus `GRYPE_DB_CACHE_DIR` and
   `GRYPE_DB_MAX_ALLOWED_BUILT_AGE` set by the Makefile. No proxy variable is passed: the scan itself makes no network request,
   because the database was imported beforehand and update checks are off.
   The gate then compares the whole effective configuration recorded in the report (`descriptor.configuration`) with the
   committed [`security/grype-expected-config.json`](../security/grype-expected-config.json): objects must have exactly the same
   keys, arrays the same length, and scalars the same type and value. Any difference fails, and so does a missing key or a new
   or unknown one, which makes a Grype upgrade that adds settings fail until the file is reviewed. Only these fields may vary:
   - `db.cache-dir`: the absolute path of the database cache in the checkout; it differs per machine and does not choose the
     database, whose schema, build time and validity are checked through `descriptor.db.status`;
   - `file`: the path the report was written to; it does not influence matching.

   Both must still be non-empty strings. `db.max-allowed-built-age` is not free either: it must equal
   `GRYPE_DB_MAX_AGE_HOURS` in nanoseconds. After a Grype bump, run `make image-scan` (it fails on the new configuration), then
   `make grype-expected-config` to rewrite the file from that report, and review every changed setting in the pull request.

   The expected file cannot weaken the scan, because the gate code also enforces hard invariants on both the effective
   configuration and the expected file, whatever the file says:
   - `only-fixed` and `only-notfixed` are `false`, `ignore-wontfix` is empty, and `exclude`, `vex-documents` and `vex-add` are
     empty;
   - `ignore` holds exactly Grype's four built-in kernel-header rules (hard-coded in the gate), nothing added or removed;
   - `distro`, `platform` and `default-image-pull-source` are empty, and `from` is null or `[]`;
   - `match.stock.using-cpes` and `match.jvm.using-cpes`, the CPE matchers enabled in the baseline, stay `true`;
   - `search.scope` is `squashed` or `all-layers`, and `by-cve` is `false`, so the IDs used by the exceptions stay stable;
   - `db.auto-update` is `false`, and `db.validate-age` and `db.validate-by-hash-on-start` are `true`;
   - the database age limit is at most 120 hours: the Makefile refuses a larger `GRYPE_DB_MAX_AGE_HOURS` and the gate fails on
     a larger `--max-db-age-hours`.

   A unit test fails when the committed expected file breaks an invariant, so a weakened regenerated file fails CI before any
   scan. Changing an invariant needs a change to `tools/security/grype_gate.py` and its review.
5. **Gate.** `tools/security/grype_gate.py` reads the Grype JSON report and `security/vulnerability-exceptions.yaml` and fails on:
   - any schema violation or expired entry in the exceptions file (the shared validator below);
   - any critical, high or unknown-severity finding that no entry lists (an unrated finding can be a critical one). A listing matches only when the vulnerability ID, the package name and
     the package version all equal Grype's `vulnerability.id`, `artifact.name` and `artifact.version`, so an ID listed for one
     package never covers another package or another version;
   - a stale entry: a listing that matches no reported finding of any severity;
   - a listed finding that Grype now reports with a different severity;
   - a report from another Grype version, for another image (the image ID or digest taken from the engine before the scan
     must appear in the report), or one that is malformed;
   - a distribution other than `alpine` at the release read from the image's own `/etc/alpine-release` (the target also
     requires that release to belong to the pinned base image minor, `alpine:3.24`), so a distribution override cannot pass;
   - any configuration difference described above, and any ignored match in the report;
   - an invalid database, a schema other than v6, or the age limits above.

   Medium, low and negligible findings without an entry are counted in the summary but do not fail the gate. Unfixed
   critical, high and unknown findings are not exempt: they need an entry like any other.
6. **Reports.** `build/image-scan/` holds `grype.json` (the full Grype report), `summary.md` (the gate verdict, the database and
   finding counts, every failure and the accepted findings), `db-listing.json`, `db-status.json`, `image-id.txt` and
   `alpine-release.txt`. In CI the
   summary is added to the job summary and the directory is uploaded as the `image-scan` artifact (kept 30 days), also when the
   gate fails.

Network dependency: the target needs `github.com` (and its release download host) for the Grype archive on the first run, and
`grype.anchore.io` for the listing on every run and for each new database archive. Without network access it fails; it never
falls back to an unverified or older database.

On the test build of 2026-10-25 (Grype 0.121.0, Alpine 3.24.3, database built 2026-10-25T06:27:34Z) the gate passes: Grype
reports 18 findings (1 critical, 6 high, 10 medium, 1 negligible, no unknown), and the critical and high ones are exactly the
seven listed exceptions below. Run with `GRYPE_MATCH_STOCK_USING_CPES=false`, `GRYPE_DISTRO=alpine:3.10` or
`GRYPE_ONLY_FIXED=true` in the environment, `make image-scan` still reports the same 18 findings and passes, because the
variables are scrubbed. A report produced with those variables, bypassing the Makefile, fails the gate on the invariants and the
configuration comparison (and, for the distribution override, on the release check). Weakening `security/grype.yaml`
(`exclude: ["./opt/python/**"]` and `match.stock.using-cpes: false`) and regenerating the expected file with
`make grype-expected-config` drops the scan to 11 findings, and the gate fails on both invariants.

## Vulnerability exceptions

[`security/vulnerability-exceptions.yaml`](../security/vulnerability-exceptions.yaml) is the machine-readable list that the gate
consumes. `tools/security/vulnerability_exceptions.py` is the single validator, used by the gate and by
`tests/unit/test_vulnerability_exceptions.py`. Format 2 rules:

- the top level has exactly `format: 2` and `exceptions` (a list);
- each entry has exactly `id`, `package`, `version`, `component`, `severity`, `justification`, `owner`, `jira`, `created` and
  `expires`, every value a non-empty string without leading or trailing whitespace (quote dates and versions);
- `id`, `package` and `version` are copied from the Grype report; `component` is the human description;
- `severity` is `critical`, `high`, `medium`, `low` or `unknown` and must equal the reported severity;
- `jira` matches `FREES-[0-9]+` in full (ASCII digits, no trailing newline);
- `created` and `expires` are `YYYY-MM-DD` dates with `created <= today < expires`, `expires <= created + 90 days` and
  `expires <= today + 90 days`, so a back-dated entry cannot be renewed by editing `expires` alone;
- no two entries share `id`, `package` and `version`;
- the YAML is loaded strictly: duplicate keys, non-string keys, merge keys, anchors and aliases, several documents and custom
  tags are rejected instead of being resolved silently.

The unit test fails as soon as the committed file breaks a rule or an entry expires.
Current entries, all critical or high and none fixable in this repository yet:

| ID | Package and version | Severity | Why accepted | Expires |
|---|---|---|---|---|
| GO-2026-6612 | `golang.org/x/net` `v0.57.0` inside OpenTofu 1.13.2 (fixed in 0.60.0) | critical | No OpenTofu release includes the fix; the toolbox runs tofu as a short-lived client only | 2027-01-23 |
| GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6617 | same module | high | same | 2027-01-23 |
| GHSA-2v4p-qf9q-27wj | `google.golang.org/grpc` `v1.83.1` inside OpenTofu 1.13.2 (fixed in 1.83.2) | high | same | 2027-01-23 |
| GHSA-wj6h-64fc-37mp | `ecdsa` `0.19.2`, transitive of Checkov | high | No fixed release exists; Checkov uses only signature verification, the attack targets signing; mirrors the collection's entry | 2027-01-23 |

Owner: lead architect (OpenTofu entries, FREES-37) and project owner (`ecdsa`, FREES-82). Re-check whenever a new OpenTofu
release appears; the gate fails as soon as an OpenTofu bump removes a finding (stale entry) or changes the module version.

## Known limits

- linux/amd64 only.
- Transitive `apk` dependencies are not individually pinned; they come from the pinned Alpine release and are covered by the
  scan; the SBOM is still open (FREES-37).
- The gate scans the local test build. Scanning the release image built in AWS, the SBOM, signing and publication belong to
  FREES-36 and FREES-37.
