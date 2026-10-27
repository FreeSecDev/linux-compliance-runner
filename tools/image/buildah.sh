#!/usr/bin/env bash
set -euo pipefail

readonly BUILD_USER='build'
readonly WORK_ROOT="${IMAGE_BUILD_WORK:-/tmp/image-build}"
readonly STORE_ROOT="${IMAGE_BUILD_STORE:-/var/lib/image-build}"
readonly SOURCE_DIR="${IMAGE_BUILD_SOURCE:-/source}"
readonly BUILD_PATH="${IMAGE_BUILD_PATH:-/usr/local/bin:/usr/bin}"
readonly CONTEXT_DIR="${WORK_ROOT}/context"
readonly CONFIG_DIR="${WORK_ROOT}/config"
readonly RUNTIME_DIR="${WORK_ROOT}/run"
readonly EXPORT_DIR="${WORK_ROOT}/export"
readonly GRAPH_ROOT="${STORE_ROOT}/graph"
readonly LOCAL_TAG='localhost/linux-compliance-runner:build'
readonly REVISION_LABEL='org.opencontainers.image.revision'
readonly COMMIT_PATTERN='^[0-9a-f]{40}$'
readonly BUILD_DATE_PATTERN='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s build | export\n' "$0" >&2
  exit 2
}

require_builder() {
  [[ "$(uname -m)" == x86_64 ]] || fail 'the image is built for linux/amd64 only'
  [[ "${EXPECTED_BUILDAH_VERSION:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'EXPECTED_BUILDAH_VERSION must be x.y.z'
  local version
  version="$(buildah --version)"
  [[ "${version}" == "buildah version ${EXPECTED_BUILDAH_VERSION} "* ]] ||
    fail "unexpected builder: ${version}; the pinned builder image must provide Buildah ${EXPECTED_BUILDAH_VERSION}"
  id -u "${BUILD_USER}" > /dev/null 2>&1 || fail "the builder image has no ${BUILD_USER} user for rootless Buildah"
}

write_configuration() {
  install -d -m 0755 "${WORK_ROOT}"
  install -d -m 0700 -o "${BUILD_USER}" -g "${BUILD_USER}" "${CONFIG_DIR}" "${RUNTIME_DIR}" "${EXPORT_DIR}"
  install -d -m 0700 -o "${BUILD_USER}" -g "${BUILD_USER}" "${GRAPH_ROOT}"
  cat > "${CONFIG_DIR}/storage.conf" << STORAGE
[storage]
driver = "overlay"
runroot = "${RUNTIME_DIR}/storage"
graphroot = "${GRAPH_ROOT}"
STORAGE
  cat > "${CONFIG_DIR}/registries.conf" << 'REGISTRIES'
unqualified-search-registries = []
short-name-mode = "enforcing"
REGISTRIES
  printf '{"auths": {}}\n' > "${CONFIG_DIR}/auth.json"
  chown "${BUILD_USER}:${BUILD_USER}" "${CONFIG_DIR}/storage.conf" "${CONFIG_DIR}/registries.conf" "${CONFIG_DIR}/auth.json"
}

as_build_user() {
  runuser -u "${BUILD_USER}" -- env -i \
    PATH="${BUILD_PATH}" \
    HOME="/home/${BUILD_USER}" \
    XDG_RUNTIME_DIR="${RUNTIME_DIR}" \
    BUILDAH_ISOLATION=chroot \
    CONTAINERS_STORAGE_CONF="${CONFIG_DIR}/storage.conf" \
    CONTAINERS_REGISTRIES_CONF="${CONFIG_DIR}/registries.conf" \
    REGISTRY_AUTH_FILE="${CONFIG_DIR}/auth.json" \
    "$@"
}

require_commit() {
  [[ "${EXPECTED_COMMIT:-}" =~ ${COMMIT_PATTERN} ]] || fail 'EXPECTED_COMMIT must be a full commit SHA'
}

check_revision() {
  local revision
  revision="$(as_build_user buildah inspect --type image \
    --format "{{index .Docker.Config.Labels \"${REVISION_LABEL}\"}}" "${LOCAL_TAG}")"
  [[ "${revision}" == "${EXPECTED_COMMIT}" ]] ||
    fail "the built image carries revision ${revision}, expected ${EXPECTED_COMMIT}"
}

build() {
  require_commit
  [[ "${BUILD_DATE:-}" =~ ${BUILD_DATE_PATTERN} ]] || fail 'BUILD_DATE must be a UTC RFC 3339 time such as 2026-10-27T12:00:00Z'
  [[ -f "${SOURCE_DIR}/Containerfile" ]] || fail "${SOURCE_DIR} must hold the archived commit (Containerfile missing)"
  require_builder
  write_configuration
  install -d -m 0755 -o "${BUILD_USER}" -g "${BUILD_USER}" "${CONTEXT_DIR}"
  cp -R "${SOURCE_DIR}/." "${CONTEXT_DIR}/"
  chown -R "${BUILD_USER}:${BUILD_USER}" "${CONTEXT_DIR}"
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
    "${CONTEXT_DIR}" >&2
  check_revision
  printf 'built %s from %s with Buildah %s\n' "${LOCAL_TAG}" "${EXPECTED_COMMIT}" "${EXPECTED_BUILDAH_VERSION}" >&2
}

export_archive() {
  require_commit
  require_builder
  write_configuration
  check_revision
  local archive="${EXPORT_DIR}/image.tar"
  rm -f "${archive}"
  as_build_user buildah push --quiet "${LOCAL_TAG}" "docker-archive:${archive}:${LOCAL_TAG}" >&2
  [[ -s "${archive}" ]] || fail 'buildah wrote no archive'
  cat "${archive}"
  rm -f "${archive}"
}

main() {
  [[ $# -eq 1 ]] || usage
  case "$1" in
    build) build ;;
    export) export_archive ;;
    *) usage ;;
  esac
}

main "$@"
