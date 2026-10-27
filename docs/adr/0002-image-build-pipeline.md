# 0002. Release image build on GitHub-hosted runners, bound to its digest

- **Status:** proposed (amended 2026-10-27)
- **Date:** 2026-10-26, amended 2026-10-27
- **Deciders:** project owner (build location), lead architect
- **Jira:** FREES-36
- **Pull requests:** [linux-compliance-runner#8](https://github.com/FreeSecDev/linux-compliance-runner/pull/8) (the
  superseded CodeBuild design), [linux-compliance-runner#9](https://github.com/FreeSecDev/linux-compliance-runner/pull/9)
  (this amendment)
- **Related:** collection repository [0007](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0007-registry-build-and-signing.md), [0012](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0012-github-native-releases-and-packages.md), [0014](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0014-aws-account-bootstrap.md); [0001](0001-toolbox-image.md)

## Amendment of 2026-10-27

The first version of this ADR built the image in AWS CodeBuild and staged it in a private ECR repository (merged in
pull request 8). Its AWS resources were never created: collection pull request 51 was closed unmerged. On 2026-10-27
the product owner decided to build the image on GitHub-hosted runners and to use AWS only for VM golden images
(Packer, later). This amendment replaces the CodeBuild design. The reasons:

- **No technical reason for AWS.** Collection ADR 0007 required an AWS build only because the original brief said so;
  it gave no technical reason.
- **Provenance now covers the build.** Collection ADR 0012 recorded a weakness of the CodeBuild path: its build steps
  were not covered by cryptographic provenance, because the attestation was issued by the GitHub workflow that only
  triggered CodeBuild. Built in the workflow itself, the SLSA provenance of `actions/attest-build-provenance` names the
  workflow file, commit and run that executed the real build steps.
- **Equivalent isolation, no new trust.** GitHub-hosted runners are single-use VMs, as CodeBuild environments were.
  The build runs in a job that holds no write credential, as the CodeBuild build did, and the push happens on a
  different VM. GitHub was already in the trust chain, because it triggered the build, held the code and published
  the image.
- **Less to defend.** The CodeBuild path needed a privileged build container, a build role, 26 `StartBuild` Deny
  statements, an inline gate buildspec in the collection stack and an ECR staging repository. All of that disappears,
  and the workflow holds no AWS credential of any kind.

## Context

The image must be built from reviewed `main` only, scanned, described by an SBOM, signed, attested and published to
GHCR, and consumed by digest. A FREES-36 review requirement adds that the vulnerability scan must be bound to the
digest that was built, not to a tag or a local image ID. AGENTS.md forbids publishing a release image built anywhere
else, and forbids publishing when any scan, SBOM, signature or smoke test step fails.

## Decision

### Jobs and credentials

`.github/workflows/image-build.yml` runs on pushes to `main` that change an image input and on dispatch, only on
`main`, in the `release` environment. Top-level permissions are `{}`. Five jobs, each on its own single-use VM, with
only the `GITHUB_TOKEN` permissions it needs:

| Job | Permissions | Holds a write or package token | Runs untrusted bytes |
|---|---|---|---|
| `build` | `contents: read` | no | the build (`RUN` steps, downloads) |
| `push` | `contents: read`, `packages: write` | yes | no: it parses the archive only before the registry login, with member names derived from the trusted job output; after the login only crane reads it to push it |
| `smoke` | `contents: read` | no | the image under test |
| `scan` | `contents: read`, `packages: read` | read only | one `cat /etc/alpine-release` in the image (no network, no capabilities) |
| `publish` | `contents: read`, `packages: write`, `id-token: write`, `attestations: write` | yes | no |

The `contents: read` token is read-only on a public repository. The build therefore runs on a VM where nothing can
be stolen that grants more than the build already controls: its own output.

### Build (`build` job)

- **Builder:** rootless Buildah from `quay.io/buildah/stable` pinned by index digest (`v1.43.5-immutable`), run with
  Docker on `ubuntu-24.04`. Renovate updates the tag and digest together in the `Makefile`. The script refuses a builder
  whose `buildah --version` differs from the version in the tag. The runner's own Buildah is not used: it comes from
  the runner image's apt packages and cannot be pinned by digest.
- **Confinement of the builder container:** not privileged.
  - `--cap-drop ALL`, then only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID` and `SYS_CHROOT`. These cover
    preparing the directories and `runuser` to the build user. `SYS_CHROOT` is needed because Docker's profile allows
    `chroot` only with that capability.
  - Seccomp profile `tools/image/seccomp-buildah.json`: the default profile of Docker 29.5.3 (`moby/profiles`
    `seccomp/default.json` as vendored at moby commit `285b471`, SHA-256 `536529b6...`), with `clone`, `clone3`,
    `mount`, `pivot_root`, `setns`, `umount`, `umount2` and `unshare` moved into one unconditional allow entry.
    Everything else the default blocks stays blocked, among them `bpf`, `keyctl`, `add_key`, `perf_event_open`,
    `userfaultfd`, `io_uring_*`, `kexec_*` and module loading. Unit tests pin this: the canonical SHA-256 of the
    profile without the added entry (`1b028997...`) equals that of Docker's default with the eight names removed, and
    17 dangerous syscalls stay unreachable with the granted capabilities.
  - `--security-opt apparmor=unconfined`, because Docker's default AppArmor profile denies `mount`; the workflow also
    sets `kernel.apparmor_restrict_unprivileged_userns=0`, because Ubuntu 24.04 restricts unprivileged user
    namespaces through AppArmor.
  - Storage is the kernel's native overlay driver in a user namespace, so `/dev/fuse` is not passed in.
  - `--security-opt no-new-privileges` is not set: it breaks the setuid `newuidmap` that rootless Buildah needs.
- **Rootless:** Buildah runs as the image's unprivileged `build` user (`buildah info` must report `rootless=true`),
  with chroot isolation.
- **What is built:** `make image-build` refuses to run unless the checkout is at `github.sha` (`EXPECTED_COMMIT`). It
  builds a `git archive` of `HEAD` (Containerfile, `.dockerignore`, `toolbox/`), and takes `tools/image/buildah.sh` and
  the seccomp profile from `git show HEAD:`, so nothing from the working tree reaches the build. The build is Docker
  format (the Containerfile `SHELL` then applies to `RUN` exactly as in the Docker test build), `--pull=always`,
  `--layers=false`, `VCS_REF` set to the commit. The script refuses an image whose `org.opencontainers.image.revision`
  label is not the commit.
- **Output:** the image is exported with `buildah push docker-archive:` and streamed to `build/image-build/image.tar`.
  The job records the archive's SHA-256, the image config digest and the revision label (`BUILT_COMMIT`, which must
  equal `github.sha`) as job outputs, and uploads the archive as the `image-archive` artifact.

The build was tested locally with this exact confinement (Docker 29.5.3 on WSL2, which has no AppArmor) on
2026-10-27: the full Containerfile built rootless and was exported in 85 seconds, and the image passed the smoke
tests. Without the added syscalls, `unshare(CLONE_NEWUSER)` is refused. The AppArmor part and native overlay on the
runner's kernel are verified only by the first real run. If native overlay fails there, the fallback is fuse-overlayfs
(`mount_program = "/usr/bin/fuse-overlayfs"` and `--device /dev/fuse`), recorded here when it happens.

### Push, by digest (`push` job)

- The archive comes from the build VM, so it is untrusted input. Before the job logs in to any registry,
  `make image-archive-check` refuses it unless:
  - its SHA-256 equals the `build` job's output;
  - `manifest.json` names exactly one image whose config member is `<config digest>.json`. The member name is
    derived from the trusted job output, never read from the archive, and compared with the manifest before use;
  - that member hashes to the recorded config digest and its revision label is the commit.

  Every `tar` call passes `--` before the member name, so no archive content can become a `tar` option. (The first
  version of this check passed the archive's `Config` value to `tar`, which a crafted archive could turn into
  `--use-compress-program=...`; a unit test now proves such an archive is refused without running anything.)
  After the login, `make image-push` only re-checks the archive's SHA-256 and lets crane, a Go library without a
  shell, read it to push it.
- It first proves that the release tag does not exist yet (see re-runs below). Then crane pushes the archive to
  `ghcr.io/freesecdev/linux-compliance-runner` as `candidate-<commit>-<run>-<attempt>`, and `make image-push` requires:
  - the manifest bytes GHCR serves for `@<digest>` hash to the digest the tag resolves to;
  - the media type is a single Docker v2 image manifest, never an index;
  - the pushed manifest's config digest equals the config digest the build recorded;
  - the pushed image's revision label equals the commit.
- The job outputs the `name@sha256:<digest>` reference, the digest and the release tag.

### Verification and publication

- **Every later step names the digest:** scan, SBOM, signature, attestations, verification and the release tag all
  use `ghcr.io/freesecdev/linux-compliance-runner@sha256:<digest>`.
- **Smoke tests** (`smoke` job, no package token): `make image-smoke-archive` checks the same archive hash, config
  digest and label, loads it, and runs the smoke tests. The config digest names the image's layers (`rootfs.diff_ids`),
  and the push job checked that the pushed digest carries that config, so the tested file system is the published one.
- **Scan** (`scan` job, read-only token): `make image-pull` pulls the digest and checks `RepoDigests` and the label.
  `make image-scan` scans `registry:<name>@sha256:<digest>`; the gate's `--image-reference` option (unchanged)
  refuses tags, and requires the scanned input to be exactly that reference, the scanned manifest digest to equal it
  and the media type to be a single image manifest. Syft 1.55.0 writes SPDX and CycloneDX SBOMs of the digest in the
  same read-only job.
- **Publish** (`publish` job): `make sbom-check` re-checks that both SBOMs describe the digest. The release tag must
  still be absent. cosign keyless signs the digest with the workflow identity, `actions/attest-build-provenance` adds
  SLSA provenance and `actions/attest` the SPDX SBOM attestation, both pushed to GHCR. `actions/attest` is used for
  the SBOM instead of `actions/attest-sbom`, because `attest-sbom` is deprecated upstream in favour of it and wraps an
  older `actions/attest`.
- **The workflow verifies its own output:** `make verify-release` runs `cosign verify` with the exact certificate
  identity, issuer, repository, `refs/heads/main` and the commit SHA. It runs `gh attestation verify` for both
  predicate types with `--signer-workflow .../image-build.yml@refs/heads/main`, `--signer-digest <commit>`,
  `--source-ref refs/heads/main`, `--source-digest <commit>` and `--deny-self-hosted-runners`, and records
  `gh --version` (`--signer-workflow` is matched exactly only from gh 2.103.3; `--signer-digest` binds the signer on
  any version).
- **Release tag last:** only then does `make image-release` add the tag `<commit>-<run>-<attempt>` to the verified
  digest with crane, after proving again that the tag is absent, and checks that the tag resolves to the digest. A run
  that fails earlier leaves only an unsigned `candidate-` tag.

### Re-runs

`github.run_number` stays the same when a run is re-run; only `github.run_attempt` changes. Both tags therefore carry
the attempt. A re-run builds a new digest (the build is not bit-reproducible) and publishes it as a new release
`<commit>-<run>-<attempt>`; it never moves or reuses a tag. The absence of the release tag is checked before the push
and again before signing, so no run signs a digest it cannot tag.

The absence check fails closed: only a registry answer of `MANIFEST_UNKNOWN` or `NAME_UNKNOWN` counts as absent. Any
other error (network, 5xx, 401) stops the job. Before the first push only, a `DENIED` token answer is also accepted,
because the package may not exist yet; if the token really lacks access, the push that follows fails. That allowance
is honoured only as a `make` command-line argument on the nested call inside `image-push`, never from the
environment (`GITHUB_ENV` included).

Re-running a successful old run therefore publishes a fresh build of an older `main` commit under a new tag. Only
repository writers can do this; it is an operator action.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| AWS CodeBuild with ECR staging (the first version of this ADR) | Superseded on 2026-10-27: no technical reason for AWS, privileged build container, build role with 26 Deny statements, inline gate buildspec, and provenance that did not cover the build |
| Build and push in one job | The `packages: write` token would sit on the build VM, where anything that leaves the builder container could read it from the runner process or the Docker config |
| `seccomp=unconfined` and fuse-overlayfs with `/dev/fuse` (the first version of this amendment) | Not the minimum: eight added syscalls on top of Docker's default profile, six capabilities and native overlay are enough |
| Runner's own Buildah from apt | Not pinnable by digest; the runner image may change it at any time |
| Docker BuildKit (`docker build`) | The Jira plan prescribes Buildah; Buildah keeps the build rootless |
| Privileged builder container | Not needed |
| OCI archive (`oci-archive:`) | Converts the Docker image config to OCI, which drops `SHELL`; the Docker archive keeps the config bytes and therefore the config digest |
| Push the release tag immediately | A run that later fails the scan or verification would leave a release-looking tag; the candidate tag is unsigned and never used |
| Release tag without the run attempt | A re-run would sign a new digest and then fail to tag it |
| Scan the image in the local engine (`docker:`) | The engine's image ID is not the registry digest; a registry scan is bound to the exact manifest |
| OCI image format | Buildah drops `SHELL` in OCI format, so `RUN` would differ from the tested Docker build |

## Benefits

The bytes built in the workflow are the bytes tested, scanned, described, signed, attested and published, and the
provenance names the run that built them. No AWS credential, role or resource is involved. The build job holds no
write credential.

## Trade-offs

- The builder container runs without AppArmor confinement and with eight extra namespace and mount syscalls, so that
  the unprivileged build user can create a user namespace.
- The image travels between jobs as an artifact of about 800 MB uncompressed, kept for 7 days.
- The candidate digest is in GHCR before it passes the scan; it is unsigned and unattested, so a consumer that verifies
  as documented never adopts it.

## Security implications

- **Residual: GitHub-hosted runner trust.** The build depends on the integrity of GitHub's hosted runner VMs and their
  images, in addition to GitHub as code host, workflow engine, OIDC issuer and registry, which it already depended on.
  A compromised runner image could alter the build. Mitigations: single-use VMs, a builder pinned by digest, a base
  image and every tool pinned by digest or checksum, provenance verified with `--deny-self-hosted-runners`, and the
  Grype gate on the published bytes. This is accepted by the product owner's decision of 2026-10-27.
- **Residual: a build-time escape.** Code that leaves the builder container during the build reaches the build VM, with
  the runner's passwordless `sudo`. That VM holds only the read-only `contents: read` token and the runner's own
  token for this run's artifacts and the Actions cache (no workflow in this repository restores a cache: `setup-uv`
  and `setup-node` run with caching off). So the escape can change the build's output, which a compromised build
  step controls anyway. It
  cannot push to the package, sign or attest. The recorded archive hash and config digest then bind every later job to
  whatever the build produced, and the scan and smoke tests run on those bytes.
- **Residual: tokens in the other jobs.** `push` and `publish` hold `packages: write`, and `scan` holds
  `packages: read`, on their own VMs. They run no build step. `scan` runs one `cat` inside the image, with
  `--network=none`, `--cap-drop=ALL`, `--read-only` and `no-new-privileges`, and the smoke tests run in `smoke`, which
  holds no package token. "Logged out" in a job means "not in the Docker config or the step environment"; the job
  token stays readable on that VM until the job ends.
- **The `release` environment does not restrict `packages: write`.** Any workflow file on any branch of this
  repository can declare `permissions: packages: write` and push to the package or move its tags without the
  environment. The repository's `default_workflow_permissions: read` covers only workflows that declare nothing. The
  real controls are write access to the repository (the owner and the bots), the `main` ruleset, and, for consumers,
  the digest pin plus the cosign identity and attestations bound to `image-build.yml@refs/heads/main`. The Make guards
  on `GITHUB_ACTIONS`, `GITHUB_REF` and `GITHUB_WORKFLOW_REF` only stop accidents.
- The image revision label is a consistency check: it comes from the same build inputs. The proof of what was built is
  the provenance, which `make verify-release` checks against the commit.

## Operational consequences

- No AWS bootstrap or repository variable is needed for the image; `AWS_REGION` and `AWS_BUILD_ROLE_ARN` are not used.
- Bumping Buildah is a Renovate pull request that changes `BUILDAH_TAG` and `BUILDAH_DIGEST` together.
- The seccomp profile is re-derived by hand when Docker's default profile changes in a way the build needs; the unit
  test keeps the dangerous syscalls blocked.
- Candidate tags of failed runs stay in GHCR and can be deleted by a maintainer; nothing trusts them.
- The first push creates the GHCR package; its visibility may need to be set to public once.
