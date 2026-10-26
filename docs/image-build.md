# Image build pipeline

Scope: how the release image is built in AWS, scanned, described by an SBOM, signed, attested and published, and how
consumers pin it. Jira: FREES-36. Design rationale: [ADR 0002](adr/0002-aws-image-build-pipeline.md) here and collection
ADRs [0007](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0007-registry-build-and-signing.md),
[0012](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0012-github-native-releases-and-packages.md)
and [0014](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0014-aws-account-bootstrap.md).
The AWS resources are code in the collection repository (`infra/account`, files `image_build.tf` and
`iam_image_build_role.tf`); their cost estimate is in its
[`docs/aws/costs.md`](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/aws/costs.md).

## Flow

```text
push to main (image inputs changed) or workflow_dispatch on main
  job build   (environment release, contents: read, id-token: write)
    OIDC -> role freesecdev-gha-linux-compliance-runner-build
    make image-build        CodeBuild project freesecdev-linux-compliance-runner builds the commit with
                            rootless Buildah and pushes <commit>-<build number> to ECR staging;
                            the workflow waits and verifies commit, exported digest and the ECR record
    make image-pull         docker pull <staging>@sha256:..., revision label must equal the commit
    make image-smoke-staged smoke tests against that digest
    make image-scan         Grype scans registry:<staging>@sha256:..., gate bound to the digest
    make sbom               Syft SPDX and CycloneDX SBOMs of the same digest
    artifact image-build    build.json, scan report and summary, SBOMs (90 days)
  job publish (environment release, contents: read, id-token, packages, attestations: write)
    make image-promote      crane copy to ghcr.io/freesecdev/linux-compliance-runner, digest unchanged
    make sign               cosign keyless signature of ghcr.io/...@sha256:...
    actions/attest          SLSA build provenance and SPDX SBOM attestations, pushed to GHCR
    make verify-release     cosign verify and gh attestation verify of the digest
    artifact image-release  image.json (the release digest) and the verification output
```

A failure in any step stops the run, and nothing after it runs: nothing reaches GHCR unless the build, digest checks,
smoke tests, vulnerability gate and SBOM all passed, and the run fails if signing, attestation or verification fails.

## Build in AWS

- **Service:** CodeBuild project `freesecdev-linux-compliance-runner` in `eu-west-1`, `BUILD_GENERAL1_MEDIUM`
  (4 vCPU, 7 GB), at most one concurrent build, 45-minute build timeout and 15-minute queue timeout. The workflow
  stops the build itself after 50 minutes (`IMAGE_BUILD_TIMEOUT_MINUTES`) and the job times out after 90.
- **Source:** the public GitHub repository at the exact commit of the workflow run (`--source-version <sha>`). The
  build script refuses to run when CodeBuild's resolved commit differs from `EXPECTED_COMMIT`, and the workflow checks
  `resolvedSourceVersion` again. The build specification is [`codebuild/buildspec.yml`](../codebuild/buildspec.yml) and
  the steps are [`codebuild/build-image.sh`](../codebuild/build-image.sh), both reviewed in this repository.
- **Builder:** `quay.io/buildah/stable` pinned by index digest (`sha256:7c2b6052...`, Buildah 1.43.5, the immutable
  release tag of 2026-10-19). The script checks the Buildah version.
- **Rootless:** Buildah runs as the unprivileged `build` user of that image in a user namespace (`buildah info`
  must report `rootless=true`), with chroot isolation and fuse-overlayfs storage. User namespaces need CodeBuild
  privileged mode; an unprivileged container fails with `unshare(CLONE_NEWUSER): Operation not permitted` (tested
  locally with Docker 29 on 2026-10-26). See ADR 0002 for why privileged mode is accepted.
- **Inputs:** the Containerfile pins the base by digest and every tool by version and checksum. The docker.io base is
  pulled through the digest-only mirror `public.ecr.aws/docker/library` (Docker Hub rate limits shared CodeBuild
  addresses); a mirror can only serve the pinned digest. The Amazon ECR credential helper 0.12.0 is downloaded and
  checked against its pinned SHA-256 before use. No secret or token is passed to the build.
- **Output:** a Docker v2 image manifest (Docker format keeps the Containerfile `SHELL` for `RUN`, as in the CI test
  build) pushed to the private ECR repository `linux-compliance-runner-staging` with the immutable tag
  `<commit>-<build number>`. The build exports `IMAGE_DIGEST`, `IMAGE_TAG` and `IMAGE_REFERENCE`.

The CodeBuild service role may only write the project's log streams and push to the staging repository. The ECR
repository has immutable tags, scan on push, KMS encryption and a lifecycle rule that expires staged images 14 days
after the push.

## Digest verification

`tools/aws/image-build.sh` (run by `make image-build`) fails unless:

- CodeBuild reports exactly this build ID, status `SUCCEEDED` and `resolvedSourceVersion` equal to the commit;
- `IMAGE_DIGEST` is `sha256:<64 hex>`, `IMAGE_TAG` is `<commit>-<build number>` and `IMAGE_REFERENCE` is
  `<staging repository>@<digest>`, each exported exactly once;
- `aws ecr describe-images` for that digest returns one image, with that digest, the tag, and the Docker v2 manifest
  media type.

On failure it prints the tail of the build log. If the run is interrupted or times out it stops the build. The
record `build/image-build/build.json` holds the commit, build ID and number, builder image, staged tag, digest,
reference, push time and size.

`make image-pull` then pulls the digest reference, requires the engine to list it in `RepoDigests` and requires the
`org.opencontainers.image.revision` label to equal the checked-out commit.

## Scan bound to the digest

`make image-scan IMAGE_REF=<repository>@sha256:<digest>` scans `registry:<reference>`, so Grype fetches the manifest by
digest from the registry. The reference must match `name@sha256:<64 hex>`; a tag is refused by the Makefile and by
the gate. In addition to every rule in [`image.md`](image.md#vulnerability-gate), the gate (`--image-reference`) fails
unless:

- the report's source type is `image` and its `userInput` equals the reference exactly;
- the scanned `manifestDigest` equals the reference digest, so an index digest or another platform fails;
- the media type is a single image manifest (OCI or Docker v2), never an index;
- `--image-id` equals the same digest.

The Alpine release check reads `/etc/alpine-release` from the pulled image of the same digest. The SBOM is checked the
same way: the SPDX document must describe one root package whose version and SHA-256 checksum are the digest, and the
CycloneDX component version must equal it.

## Publication

The staged digest is copied to `ghcr.io/freesecdev/linux-compliance-runner` with tag `<commit>-<build number>`, and the
copy is accepted only if GHCR returns the same digest for the tag and serves manifest bytes that hash to it. Then:

- **Signature:** `cosign sign` keyless with the workflow's GitHub OIDC identity. Verify with:

  ```text
  cosign verify ghcr.io/freesecdev/linux-compliance-runner@sha256:<digest> \
    --certificate-identity https://github.com/FreeSecDev/linux-compliance-runner/.github/workflows/image-build.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository FreeSecDev/linux-compliance-runner \
    --certificate-github-workflow-ref refs/heads/main
  ```

- **Provenance and SBOM:** GitHub artifact attestations (`actions/attest`), pushed to GHCR next to the image. Verify
  with:

  ```text
  gh attestation verify oci://ghcr.io/freesecdev/linux-compliance-runner@sha256:<digest> \
    --repo FreeSecDev/linux-compliance-runner \
    --signer-workflow FreeSecDev/linux-compliance-runner/.github/workflows/image-build.yml \
    --predicate-type https://slsa.dev/provenance/v1
  ```

  Use `--predicate-type https://spdx.dev/Document/v2.3` for the SBOM. As collection ADR 0012 states, the provenance
  identifies the workflow that triggered, verified, scanned, copied and signed the image. It does not
  cryptographically prove what CodeBuild executed. That rests on the version-controlled build steps, the role scoping
  and the digest checks above.

The release digest is in the `image-release` artifact (`image.json`) and in the job summary. Versioned GitHub
Releases with the digest, SBOM and scan report as assets are FREES-84.

## Consuming the image

Consumers, including the collection repository, reference the image by digest only:
`ghcr.io/freesecdev/linux-compliance-runner@sha256:<digest>`. Tags are for people and are never used as a pin. Verify
the signature and attestations above before adopting a new digest.

## Credentials

| Where | Credential | Lifetime |
|---|---|---|
| GitHub to AWS | OIDC web identity for `freesecdev-gha-linux-compliance-runner-build`, trusted only for the `release` environment of this repository through `image-build.yml` on `main` | up to 1 hour (build job), 15 minutes (publish job) |
| Runner to ECR | `aws ecr get-login-password` token in the runner's Docker config, removed with `docker logout` at the end of each job | 12 hours, runner discarded after the job |
| Runner to GHCR | the job's `GITHUB_TOKEN` (`packages: write`) | the job |
| CodeBuild to ECR | the CodeBuild service role through the ECR credential helper | the build |
| Signing | Fulcio certificate for the workflow identity, logged in Rekor | minutes |

There are no long-lived keys. Pull requests and forks cannot run this workflow with AWS access, because the role
trusts only the `release` environment, which accepts `main` only.

## Running it

The workflow runs on every push to `main` that changes an image input, and on demand:

```text
gh workflow run image-build.yml --repo FreeSecDev/linux-compliance-runner --ref main
gh run watch --repo FreeSecDev/linux-compliance-runner
```

It needs the repository variables `AWS_REGION` and `AWS_BUILD_ROLE_ARN`, which `make aws-bootstrap` in the collection
repository sets after it creates the role. Until that bootstrap has been applied, the build job fails at the
credentials step.

## Known limits

- linux/amd64 only.
- The ECR credential helper's checksum comes from the same S3 origin as the binary (TLS trust only).
- A privileged CodeBuild container is needed for rootless Buildah; see ADR 0002.
- The first GHCR push creates the package; its visibility follows the organisation's package settings and may need
  to be set to public once in the package settings.
