# linux-compliance-runner

Minimal, signed, Alpine-based OCI toolbox image for the CI of
[`freesecdev.linux_compliance`](https://github.com/FreeSecDev/ansible-linux-compliance).

> **Status: pre-alpha.** No image has been published yet.

The image is a job toolbox, not a self-hosted runner service. It is built with rootless Buildah on GitHub-hosted runners,
then scanned, given an SBOM, signed with cosign and attested. It is published to
`ghcr.io/freesecdev/linux-compliance-runner` and must be consumed by digest.
See [ADR 0002](docs/adr/0002-image-build-pipeline.md), [`docs/image-build.md`](docs/image-build.md) and collection
[ADR 0007](https://github.com/FreeSecDev/ansible-linux-compliance/blob/main/docs/adr/0007-registry-build-and-signing.md).

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
