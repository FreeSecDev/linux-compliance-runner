# 0002. Release image build in AWS CodeBuild, bound to its digest

- **Status:** proposed
- **Date:** 2026-10-26
- **Deciders:** lead architect
- **Jira:** FREES-36
- **Pull requests:** pending
- **Related:** collection repository [0007](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0007-registry-build-and-signing.md), [0012](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0012-github-native-releases-and-packages.md), [0014](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0014-aws-account-bootstrap.md); [0001](0001-toolbox-image.md)

## Context

Collection ADR 0007 decides that CodeBuild builds the image with rootless Buildah and pushes it to a private ECR
staging repository. The triggering GitHub workflow then scans the staged digest, generates the SBOM, copies the image
by digest to GHCR, and signs and attests it. AGENTS.md forbids release builds on local machines and GitHub-hosted
runners. A FREES-36 review requirement adds that the vulnerability scan must be bound to the digest that was built,
not to a tag or a local image ID.

## Decision

- **Orchestration:** `.github/workflows/image-build.yml` runs on `main` only, in the protected `release` environment,
  on pushes that change an image input and on dispatch. It has two jobs: `build`, with `id-token: write` and
  `contents: read`, and `publish`, which adds `packages: write` and `attestations: write`. The top-level
  permissions are `{}`.
- **Build:** CodeBuild with a digest-pinned `quay.io/buildah/stable` image. Buildah runs rootless as the `build` user,
  with chroot isolation and fuse-overlayfs. It builds in Docker format, so the Containerfile `SHELL` applies to `RUN`
  exactly as in the Docker test build, and pushes `<commit>-<build number>` to ECR staging.
- **Gate:** what runs in the build container is decided by the inline buildspec of the `NO_SOURCE` project in the
  collection stack, not by the caller and not by this repository.
  - The gate validates `EXPECTED_COMMIT` and `BUILD_DATE`, clones `main` without a credential, requires
    `git merge-base --is-ancestor "$EXPECTED_COMMIT" origin/main`, checks out that commit, and runs its
    `codebuild/build-image.sh` under a 35-minute `timeout`.
  - A check inside `build-image.sh` alone would not help: whoever chooses the source also chooses the script.
  - The gate was exercised in the pinned builder on 2026-10-26. A `main` commit passed; a pull request branch head,
    an unknown SHA, a short SHA and a SHA followed by a newline were refused.
- **Overrides:** the build role denies every code-selecting `StartBuild` override:
  - 26 `Null` Deny statements on the `StartBuild` condition keys;
  - an allow-list of the two environment variable names.

  This corrects the earlier claim that IAM cannot restrict overrides; it can. `sourceVersion` has no key, but it is
  irrelevant without a source. `timeoutInMinutesOverride` has no key either, and the gate's `timeout` bounds it.
- **Credentials in the workflow:** `configure-aws-credentials` runs with `output-env-credentials: false`, and the
  keys go only to the steps that call AWS. The smoke tests run after `docker logout` with no credential at all.
  Grype, Syft and crane hold only the ECR pull token.
- **Privileged CodeBuild container (proposed; owner acceptance pending in collection ADR 0014):** rootless Buildah
  needs a user namespace.
  - In an unprivileged container, `unshare(CLONE_NEWUSER)` is denied; this was tested locally with Docker 29.
  - Root Buildah without `CAP_SYS_ADMIN` also re-executes into a user namespace and fails the same way. An
    independent review reproduced both with `--isolation chroot` and vfs.
  - The project therefore uses `privileged_mode = true`. Checkov CKV_AWS_316 is baselined for that one project in
    the collection repository, and a unit test pins the project as a whole block.
  - **Containment:**
    - The build runs in a single-use CodeBuild environment, and Buildah itself runs as a non-root user.
    - Only a `main` commit chosen through the gate runs in it.
    - No secret is present. The only credential is the service role, which can write logs and push to the staging
      repository and nothing else.
    - The concurrency limit is 1, and the gate bounds the run time.
- **Digest verification:** the workflow accepts a build only if CodeBuild reports success, the resolved commit
  matches, and the exported digest, tag and reference are consistent. ECR must also return that digest with the tag
  and a single-image manifest type. The pulled image's revision label must equal the commit.
- **Scan bound to the digest:** Grype scans `registry:<staging>@sha256:<digest>`. The gate's `--image-reference`
  option requires the following, and refuses tags:
  - the scanned input is exactly that reference;
  - the scanned manifest digest equals it;
  - the media type is a single image manifest.
- **SBOM:** Syft 1.55.0. Its release checksums are verified with cosign against Syft's release workflow, as Grype's
  are. The SPDX root package must carry the digest as version and checksum.
- **Publication:** crane 0.22.1, pinned by SHA-256, copies the digest to GHCR. The copy must keep the digest. Then
  cosign keyless signs the image, `actions/attest` adds SLSA provenance and SPDX SBOM attestations pushed to the
  registry, and both are verified in the same job. GHCR is canonical, and consumers pin the digest.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Unprivileged CodeBuild with root Buildah (`--isolation chroot`, vfs) | Fails: Buildah needs `CAP_SYS_ADMIN` or a user namespace, and neither is available unprivileged |
| Kaniko or BuildKit rootless | ADR 0007 and the Jira plan prescribe Buildah; BuildKit rootless needs the same user namespaces |
| EC2 builder | More IAM surface, a reaper and AMI maintenance for the same result; ADR 0007 chose CodeBuild |
| Curated CodeBuild image with Docker | Not pinnable by digest and needs privileged mode anyway |
| Scan the image in the local engine (`docker:`) | The engine's image ID is not the registry digest; a registry scan is bound to the exact manifest |
| Push to GHCR from CodeBuild | Needs a long-lived GitHub token in AWS (ADR 0007) |
| OCI format | Buildah drops `SHELL` in OCI format, so `RUN` would differ from the tested Docker build |

## Benefits

The bytes built in AWS are the bytes scanned, described, signed and published. Every check names the digest, and
no credential outlives a job.

## Trade-offs

The build container is privileged. The workflow pulls the image from ECR to the runner for the smoke tests and the
scan, which adds internet egress, covered by the free tier at this volume. Provenance does not prove what CodeBuild
executed (collection ADR 0012).

## Security implications

- The role trust is pinned to the `release` environment, the repository and owner IDs, and `image-build.yml` on
  `main` (collection ADR 0014). Pull requests and forks get no AWS role.
- The build role denies every code-selecting `StartBuild` override, and the gate builds only `main` commits. So even
  a leaked session or a compromised step cannot run unreviewed code in the privileged container. The residuals are:
  - `timeoutInMinutesOverride`: a cost risk, bounded by the gate's `timeout`;
  - back-to-back builds: about 14.40 USD a day at most, with the budget alert as the backstop;
  - `debugSessionEnabled`: inert without `ssmmessages:*`.
- The image revision label is a consistency check: it comes from the same build inputs.
- Base images are pinned by digest. The digest-only mirror is a rate-limit workaround, not the control.

## Operational consequences

- The collection's `make aws-bootstrap` applies the AWS resources and sets the repository variables `AWS_REGION` and
  `AWS_BUILD_ROLE_ARN` here.
- Bumping Buildah means changing the image digest in the collection's `infra/account` and `EXPECTED_BUILDAH_VERSION`
  here together.
- Staged images expire after 14 days; GHCR keeps the published digests.
