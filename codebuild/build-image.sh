#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_BUILDAH_VERSION='1.43.5'
readonly ECR_LOGIN_VERSION='0.12.0'
readonly ECR_LOGIN_SHA256='a22ab6d59dbac777b8fb31984709461da00a4c778b6ae14c8d3729e8d5ded1a6'
readonly ECR_LOGIN_URL="https://amazon-ecr-credential-helper-releases.s3.us-east-2.amazonaws.com/${ECR_LOGIN_VERSION}/linux-amd64/docker-credential-ecr-login"
readonly BUILD_USER='build'
readonly WORK_ROOT='/tmp/image-build'
readonly CONTEXT_DIR="${WORK_ROOT}/context"
readonly CONFIG_DIR="${WORK_ROOT}/config"
readonly RUNTIME_DIR="${WORK_ROOT}/run"
readonly STORAGE_ROOT="${WORK_ROOT}/storage"
readonly DIGEST_FILE="${WORK_ROOT}/digest"
readonly RESULT_FILE="${WORK_ROOT}/result.env"
readonly LOCAL_TAG='localhost/linux-compliance-runner:build'
readonly REPOSITORY_PATTERN='^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*$'
readonly BUILD_DATE_PATTERN='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

require_inputs() {
  [[ "$(uname -m)" == x86_64 ]] || fail 'the image is built for linux/amd64 only'
  [[ "${STAGING_REPOSITORY_URI:-}" =~ ${REPOSITORY_PATTERN} ]] ||
    fail 'STAGING_REPOSITORY_URI must be an ECR repository URI in this account'
  [[ "${EXPECTED_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] || fail 'EXPECTED_COMMIT must be a full commit SHA'
  [[ "${CODEBUILD_RESOLVED_SOURCE_VERSION:-}" == "${EXPECTED_COMMIT}" ]] ||
    fail 'the checked-out commit is not the commit the workflow asked for'
  [[ "${BUILD_DATE:-}" =~ ${BUILD_DATE_PATTERN} ]] || fail 'BUILD_DATE must be a UTC RFC 3339 time such as 2026-10-26T12:00:00Z'
  [[ "${CODEBUILD_BUILD_NUMBER:-}" =~ ^[0-9]+$ ]] || fail 'CODEBUILD_BUILD_NUMBER is missing'
  [[ -n "${CODEBUILD_SRC_DIR:-}" && -f "${CODEBUILD_SRC_DIR}/Containerfile" ]] || fail 'the source checkout has no Containerfile'
  local version
  version="$(buildah --version)"
  [[ "${version}" == "buildah version ${EXPECTED_BUILDAH_VERSION} "* ]] ||
    fail "unexpected builder: ${version}; the CodeBuild image must provide Buildah ${EXPECTED_BUILDAH_VERSION}"
  id -u "${BUILD_USER}" > /dev/null 2>&1 || fail "the builder image has no ${BUILD_USER} user for rootless Buildah"
}

install_credential_helper() {
  local download="${WORK_ROOT}/docker-credential-ecr-login"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 30 \
    --max-time 300 --output "${download}" "${ECR_LOGIN_URL}"
  printf '%s  %s\n' "${ECR_LOGIN_SHA256}" "${download}" | sha256sum --check --strict -
  install -m 0755 "${download}" /usr/local/bin/docker-credential-ecr-login
  rm -f "${download}"
}

write_user_configuration() {
  local registry="${STAGING_REPOSITORY_URI%%/*}"
  install -d -m 0700 -o "${BUILD_USER}" -g "${BUILD_USER}" "${RUNTIME_DIR}" "${STORAGE_ROOT}" "${CONFIG_DIR}"
  cat > "${CONFIG_DIR}/storage.conf" << STORAGE
[storage]
driver = "overlay"
runroot = "${RUNTIME_DIR}/storage"
graphroot = "${STORAGE_ROOT}"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
mountopt = "nodev,fsync=0"
STORAGE
  cat > "${CONFIG_DIR}/registries.conf" << 'REGISTRIES'
unqualified-search-registries = []
short-name-mode = "enforcing"

[[registry]]
prefix = "docker.io/library"
location = "docker.io/library"

[[registry.mirror]]
location = "public.ecr.aws/docker/library"
pull-from-mirror = "digest-only"
REGISTRIES
  printf '{"credHelpers": {"%s": "ecr-login"}}\n' "${registry}" > "${CONFIG_DIR}/auth.json"
  chown "${BUILD_USER}:${BUILD_USER}" "${CONFIG_DIR}/storage.conf" "${CONFIG_DIR}/registries.conf" "${CONFIG_DIR}/auth.json"
  chmod 0600 "${CONFIG_DIR}/auth.json"
}

copy_build_context() {
  install -d -m 0755 -o "${BUILD_USER}" -g "${BUILD_USER}" "${CONTEXT_DIR}"
  cp -R "${CODEBUILD_SRC_DIR}/Containerfile" "${CODEBUILD_SRC_DIR}/Containerfile.dockerignore" \
    "${CODEBUILD_SRC_DIR}/toolbox" "${CONTEXT_DIR}/"
  chown -R "${BUILD_USER}:${BUILD_USER}" "${CONTEXT_DIR}"
}

as_build_user() {
  runuser -u "${BUILD_USER}" -- env -i \
    PATH=/usr/local/bin:/usr/bin \
    HOME="/home/${BUILD_USER}" \
    XDG_RUNTIME_DIR="${RUNTIME_DIR}" \
    BUILDAH_ISOLATION=chroot \
    CONTAINERS_STORAGE_CONF="${CONFIG_DIR}/storage.conf" \
    CONTAINERS_REGISTRIES_CONF="${CONFIG_DIR}/registries.conf" \
    REGISTRY_AUTH_FILE="${CONFIG_DIR}/auth.json" \
    AWS_REGION="${AWS_REGION:-}" \
    AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-}" \
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI="${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:-}" \
    "$@"
}

build_and_push() {
  local tag="${EXPECTED_COMMIT}-${CODEBUILD_BUILD_NUMBER}"
  as_build_user buildah info --format '{{.host.rootless}}' | grep -qx true || fail 'Buildah is not running rootless'
  as_build_user buildah build \
    --isolation chroot \
    --layers=false \
    --pull=always \
    --format docker \
    --file "${CONTEXT_DIR}/Containerfile" \
    --ignorefile "${CONTEXT_DIR}/Containerfile.dockerignore" \
    --target toolbox \
    --build-arg "VCS_REF=${EXPECTED_COMMIT}" \
    --build-arg "BUILD_DATE=${BUILD_DATE}" \
    --tag "${LOCAL_TAG}" \
    "${CONTEXT_DIR}"
  as_build_user buildah push \
    --digestfile "${DIGEST_FILE}" \
    --format v2s2 \
    --retry 3 \
    "${LOCAL_TAG}" "docker://${STAGING_REPOSITORY_URI}:${tag}"
  local digest
  digest="$(cat "${DIGEST_FILE}")"
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "buildah reported an invalid digest: ${digest}"
  {
    printf 'export IMAGE_DIGEST=%s\n' "${digest}"
    printf 'export IMAGE_TAG=%s\n' "${tag}"
    printf 'export IMAGE_REFERENCE=%s@%s\n' "${STAGING_REPOSITORY_URI}" "${digest}"
    printf 'export BUILDAH_VERSION=%s\n' "${EXPECTED_BUILDAH_VERSION}"
  } > "${RESULT_FILE}"
  printf 'pushed %s:%s as %s\n' "${STAGING_REPOSITORY_URI}" "${tag}" "${digest}"
}

main() {
  require_inputs
  rm -rf "${WORK_ROOT}"
  install -d -m 0755 "${WORK_ROOT}"
  install_credential_helper
  write_user_configuration
  copy_build_context
  build_and_push
}

main "$@"
