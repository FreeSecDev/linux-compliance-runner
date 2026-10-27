# Image build pipeline

Scope: how the release image is built on GitHub-hosted runners, tested, scanned, described by an SBOM, signed, attested
and published, and how consumers pin it. Jira: FREES-36. Design rationale: [ADR 0002](adr/0002-image-build-pipeline.md)
here and collection ADRs
[0007](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0007-registry-build-and-signing.md)
and [0012](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0012-github-native-releases-and-packages.md).
No AWS account, role or resource is involved; AWS is used only for VM golden images (collection ADR 0008).

## Flow

```text
push to main (image inputs changed) or workflow_dispatch on main, environment release
  job build    (contents: read; no package or OIDC token)
    make image-build          git archive of HEAD (= github.sha), rootless Buildah in the pinned
                              quay.io/buildah/stable image, revision label must equal the commit,
                              exported as build/image-build/image.tar (Docker archive)
    record                    outputs the archive SHA-256 and the image config digest;
                              BUILT_COMMIT must equal github.sha
    artifact image-archive    image.tar and build.json (7 days)
  job push     (contents: read, packages: write; needs build)
    make image-archive-check  before any login: archive hash, config member named after the recorded digest,
                              config digest and label
    make image-push           archive hash re-checked; release tag proven absent;
                              crane push to ghcr.io/freesecdev/linux-compliance-runner:candidate-<commit>-<run>-<attempt>;
                              served manifest, media type, config digest and label checked by digest
    record                    outputs name@sha256:..., digest, release tag <commit>-<run>-<attempt>
  job smoke    (contents: read; no package token; needs build)
    make image-smoke-archive  archive hash, config digest and label checked, docker load, smoke tests
  job scan     (contents: read, packages: read; needs push)
    make image-pull           docker pull name@sha256:..., RepoDigests and revision label checked
    make image-scan           Grype scans registry:name@sha256:..., gate bound to the digest
    make sbom                 Syft SPDX and CycloneDX SBOMs of the same digest, with the read-only token
  job publish  (contents: read, packages: write, id-token: write, attestations: write; needs push, smoke, scan)
    make sbom-check           both SBOMs must describe the digest
    make release-tag-absent   nothing is signed if the release tag already exists
    make sign                 cosign keyless signature of the digest
    attest-build-provenance   SLSA provenance of the digest, pushed to GHCR
    actions/attest            SPDX SBOM attestation of the digest, pushed to GHCR
    make verify-release       cosign verify and gh attestation verify, bound to main and the commit
    make image-release        tag <commit>-<run>-<attempt> on the verified digest, never moving or reusing a tag
```

A failure in any step stops the run, and nothing after it runs. The release tag is set only after the smoke tests,
the vulnerability gate, the SBOMs, the signature, both attestations and their verification have passed. A failed run
leaves only an unsigned, unattested `candidate-` tag, which nothing trusts.

## Build

- **Runner:** `ubuntu-24.04`, a single-use GitHub-hosted VM. The job's token is `contents: read` only, and the job
  logs in to no registry. The workflow first sets `kernel.apparmor_restrict_unprivileged_userns=0` on that VM, so that
  the unprivileged build user may create a user namespace.
- **Builder:** `quay.io/buildah/stable` pinned by index digest in the `Makefile` (`BUILDAH_IMAGE`, `BUILDAH_TAG`,
  `BUILDAH_DIGEST`; tag `v1.43.5-immutable`). Renovate updates tag and digest together. The script refuses a builder
  whose `buildah --version` is not the tag's version.
- **Container confinement:** `docker run` without `--privileged`:
  - `--cap-drop ALL --cap-add CHOWN DAC_OVERRIDE FOWNER SETUID SETGID SYS_CHROOT` (one `--cap-add` each);
  - `--security-opt seccomp=tools/image/seccomp-buildah.json`: Docker 29.5.3's default profile plus `clone`,
    `clone3`, `mount`, `pivot_root`, `setns`, `umount`, `umount2` and `unshare`; everything else the default blocks
    stays blocked (`tests/unit/tools/test_seccomp_profile.py`);
  - `--security-opt apparmor=unconfined`, because Docker's default AppArmor profile denies `mount`;
  - no `/dev/fuse`: storage is the kernel's native overlay in the user namespace.

  Inside it, `tools/image/buildah.sh` runs Buildah as the image's unprivileged `build` user (`buildah info` must report
  `rootless=true`) with chroot isolation, on the Docker volume `linux-compliance-runner-buildah`. See ADR 0002 for why
  each relaxation is needed and the fuse-overlayfs fallback.
- **Inputs:** `make image-build` refuses to run unless `HEAD` equals `EXPECTED_COMMIT` (`github.sha` in the workflow).
  The build context is a `git archive` of `HEAD` (`Containerfile`, `Containerfile.dockerignore`, `toolbox/`); the
  script and the seccomp profile come from `git show HEAD:`, so local changes never reach the build. The Containerfile
  pins the base by digest and every tool by version and checksum. Registries are fully qualified
  (`short-name-mode = "enforcing"`, no search registries). No secret or token is present in the build container.
- **Output:** a Docker v2 image (Docker format keeps the Containerfile `SHELL` for `RUN`, as in the CI test build),
  built with `--pull=always`, `--layers=false`, `--target toolbox`, `VCS_REF=<commit>` and `BUILD_DATE` from the
  commit time. The script fails unless the `org.opencontainers.image.revision` label equals the commit. A second run of
  the builder exports the image with `buildah push docker-archive:` to standard output, into
  `build/image-build/image.tar`. A Docker archive keeps the image config bytes, so the config digest recorded here is
  the one GHCR serves after the push.
- **Record:** `build/image-build/build.json` holds the commit, `built_commit`, `config_digest`, `archive_sha256`, the
  builder image and the Buildah version. The workflow fails unless `built_commit` equals `github.sha` and the archive
  matches its hash, then exports the hash and the config digest as job outputs.

`make image-build` needs only Docker (or Podman) and runs locally too. A local build is never published:
`make image-push` and `make image-release` refuse to run outside the `image-build` workflow on `main`
(`GITHUB_ACTIONS`, `GITHUB_REF` and `GITHUB_WORKFLOW_REF` are checked). These guards only stop accidents; see
[Credentials](#credentials).

## Push and digest verification

The `push` job runs on a fresh VM. It downloads the `image-archive` artifact, which is untrusted input from the build
VM. Before any registry login, `make image-archive-check` fails unless the archive's SHA-256 equals the `build` job's
output, `manifest.json` names exactly one image whose config member is `<recorded config digest>.json` (a name
derived from the trusted job output, never read from the archive), that member hashes to the recorded config
digest, and its revision label is the checked-out commit. Every `tar` call passes `--` before the member name, so
no archive content can become a `tar` option. After the login, `make image-push` fails unless:

- the archive's SHA-256 still equals the `build` job's output (crane, a Go library without a shell, then reads it);
- the release tag `<commit>-<run>-<attempt>` is proven absent (see [Re-runs](#re-runs));
- after `crane push` to `candidate-<commit>-<run>-<attempt>`, the manifest bytes GHCR serves for `name@<digest>` hash
  to the digest the candidate tag resolves to;
- the media type is `application/vnd.docker.distribution.manifest.v2+json`, a single image manifest;
- the pushed manifest's config digest equals the recorded config digest;
- the revision label in the pushed config equals the commit.

It writes `build/image-push/push.json` and the job outputs the reference
`ghcr.io/freesecdev/linux-compliance-runner@sha256:<digest>`, the digest and the release tag. Every later step uses
that reference.

## Smoke tests

The `smoke` job holds no package token. `make image-smoke-archive` checks the downloaded archive against the same hash,
config digest and label, runs `docker load`, checks the loaded image's label, and runs the smoke tests against it. The
config digest names the layer contents (`rootfs.diff_ids`, which `docker load` verifies), and the push job checked that
the published digest carries that config, so the tested file system is the published one.

## Scan bound to the digest

In the `scan` job, `make image-pull` pulls the reference, requires the engine to list it in `RepoDigests`, and
requires the revision label to equal the checked-out commit. The label comes from the same build inputs, so this is a
consistency check, not a proof; the proof is the provenance below.

`make image-scan IMAGE_REF=<repository>@sha256:<digest>` scans `registry:<reference>`, so Grype fetches the manifest by
digest from the registry. The reference must match `name@sha256:<64 hex>`; a tag is refused by the Makefile and by
the gate. In addition to every rule in [`image.md`](image.md#vulnerability-gate), the gate (`--image-reference`) fails
unless:

- the report's source type is `image` and its `userInput` equals the reference exactly;
- the scanned `manifestDigest` equals the reference digest, so an index digest or another platform fails;
- the media type is a single image manifest (OCI or Docker v2), never an index;
- `--image-id` equals the same digest.

The Alpine release check reads `/etc/alpine-release` from the pulled image of the same digest. `make sbom` then writes
the SBOMs with Syft in the same read-only job: the SPDX document must describe one root package whose version and
SHA-256 checksum are the digest, and the CycloneDX component version must equal it. The `publish` job re-checks this
with `make sbom-check` before it attests the SPDX SBOM.

## Signing, attestations and publication

- **Signature:** `cosign sign` keyless with the workflow's GitHub OIDC identity. Verify with:

  ```text
  cosign verify ghcr.io/freesecdev/linux-compliance-runner@sha256:<digest> \
    --certificate-identity https://github.com/FreeSecDev/linux-compliance-runner/.github/workflows/image-build.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository FreeSecDev/linux-compliance-runner \
    --certificate-github-workflow-ref refs/heads/main
  ```

- **Provenance and SBOM:** GitHub artifact attestations, pushed to GHCR next to the image:
  `actions/attest-build-provenance` (SLSA provenance) and `actions/attest` with the SPDX SBOM. `actions/attest-sbom`
  is not used: it is deprecated upstream in favour of `actions/attest`. Verify with gh 2.103.3 or newer (older
  versions match `--signer-workflow` as a prefix; add `--signer-digest <commit>` to bind the signer on any version):

  ```text
  gh attestation verify oci://ghcr.io/freesecdev/linux-compliance-runner@sha256:<digest> \
    --repo FreeSecDev/linux-compliance-runner \
    --signer-workflow FreeSecDev/linux-compliance-runner/.github/workflows/image-build.yml@refs/heads/main \
    --source-ref refs/heads/main --deny-self-hosted-runners \
    --predicate-type https://slsa.dev/provenance/v1
  ```

  Use `--predicate-type https://spdx.dev/Document/v2.3` for the SBOM. Because the image is built inside the workflow
  run, the provenance identifies the workflow, commit and run that executed the build steps themselves.
- **Self-verification:** `make verify-release` runs both commands above, additionally pinned to the commit
  (`--certificate-github-workflow-sha`, `--signer-digest` and `--source-digest`). It records `gh --version` in
  `build/image-release/gh-version.txt` and writes `build/image-release/verified.txt`.
- **Release tag:** `make image-release` refuses unless `verified.txt` names the same reference and the tag is proven
  absent, then sets `<commit>-<run>-<attempt>` with `crane tag` and checks that the tag resolves to the digest.

The release digest is in the `image-release` artifact (`image.json` and the verification output) and in the job
summary; the SBOMs are in the `image-sbom` artifact. Versioned GitHub Releases with the digest, SBOM and scan report as
assets are FREES-84.

## Re-runs

A re-run keeps `github.run_number` and increments `github.run_attempt`, so both tags carry the attempt. A re-run
builds a new digest (the build is not bit-reproducible) and, if every gate passes, publishes it as a new release tag;
it never moves or reuses a tag. `make release-tag-absent` runs before the push and again before signing, so no run
signs a digest it cannot tag.

The check fails closed. Only `MANIFEST_UNKNOWN` or `NAME_UNKNOWN` in crane's final error counts as absent; a network
error, a 5xx or a 401 stops the job. Before the first push only, a `DENIED` token answer is accepted, because the
package may not exist yet; if the token really lacks access, the push that follows fails. The allowance
(`ALLOW_MISSING_PACKAGE=1`) is honoured only as a `make` command-line argument, never from the environment.

Re-running a successful old run therefore publishes a fresh build of an older `main` commit. Only repository writers
can do this; treat it as an operator action.

## Consuming the image

Consumers, including the collection repository, reference the image by digest only:
`ghcr.io/freesecdev/linux-compliance-runner@sha256:<digest>`. Tags are for people and are never used as a pin; a
`candidate-` tag is never a release. Verify the signature and attestations above before adopting a new digest.

## Credentials

| Job | Credential | Untrusted code on the same VM |
|---|---|---|
| `build` | `GITHUB_TOKEN` with `contents: read` only (read-only on a public repository) and the runner's own artifact and cache token | the build |
| `push` | `GITHUB_TOKEN` with `packages: write`, in the Docker config for crane | none |
| `smoke` | `GITHUB_TOKEN` with `contents: read` only | the image under test |
| `scan` | `GITHUB_TOKEN` with `packages: read`, in the Docker config for the pull, Grype and Syft | one `cat` in the image, without network or capabilities |
| `publish` | `GITHUB_TOKEN` with `packages: write` and `attestations: write`, plus the OIDC token (`id-token: write`) for cosign keyless signing and the attestations | none |
| Signing | Fulcio certificate for the workflow identity, logged in Rekor | not applicable |

There is no AWS credential, no repository secret and no long-lived key. `docker logout` at the end of a job removes
the token from the Docker config, but the job token stays readable on that VM until the job ends; that is why the build
and the smoke tests run in jobs that hold no package token.

The `release` environment accepts `main` only, but it does not restrict `packages: write`: any workflow on any branch
of this repository can declare that permission and push to the package or move its tags without the environment. The
real controls are write access to the repository, the `main` ruleset and, for consumers, the digest pin plus the
signature and attestations bound to `image-build.yml@refs/heads/main`. Pull requests from forks never get a write
token.

The zizmor `undocumented-permissions` audit wants an explanatory comment on the first sensitive permission of each job.
YAML comments are banned in this repository (AGENTS.md rule 7), so `.github/zizmor.yml` ignores exactly those three
lines, and a unit test fails if the ignores point at any other line. The permissions are explained here:

- `packages: write` in `push` pushes the candidate image;
- `packages: read` in `scan` pulls it for the scan and the SBOMs;
- `id-token: write` in `publish` requests the OIDC token for cosign keyless signing and the attestations;
- `packages: write` in `publish` pushes the signature and attestations and sets the release tag;
- `attestations: write` creates the attestations.

## Running it

The workflow runs on every push to `main` that changes an image input, and on demand:

```text
gh workflow run image-build.yml --repo FreeSecDev/linux-compliance-runner --ref main
gh run watch --repo FreeSecDev/linux-compliance-runner
```

## Known limits

- linux/amd64 only.
- The builder container runs without AppArmor confinement and with eight extra namespace and mount syscalls
  (ADR 0002), on a single-use VM without a write token.
- The build trusts GitHub-hosted runners (ADR 0002, residual risk).
- The image travels between jobs as an artifact of about 800 MB uncompressed.
- The first GHCR push creates the package; its visibility follows the organisation's package settings and may need
  to be set to public once in the package settings.
- Candidate tags of failed runs remain until a maintainer deletes them.
