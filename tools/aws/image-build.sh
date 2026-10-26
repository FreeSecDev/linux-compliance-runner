#!/usr/bin/env bash
set -euo pipefail

readonly IMAGE_MANIFEST='application/vnd.docker.distribution.manifest.v2+json'
readonly REPOSITORY_PATTERN='^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/([a-z0-9][a-z0-9._/-]*)$'

project=''
repository_uri=''
commit=''
build_date=''
output=''
timeout_minutes=50
poll_seconds=20
build_id=''
completed=false
final_build=''

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s --project NAME --repository-uri URI --commit SHA --build-date RFC3339 --output FILE\n' "$0" >&2
  printf '       [--timeout-minutes N] [--poll-seconds N]\n' >&2
  exit 2
}

parse_arguments() {
  while [[ $# -gt 0 ]]; do
    [[ $# -ge 2 ]] || usage
    case "$1" in
      --project) project="$2" ;;
      --repository-uri) repository_uri="$2" ;;
      --commit) commit="$2" ;;
      --build-date) build_date="$2" ;;
      --output) output="$2" ;;
      --timeout-minutes) timeout_minutes="$2" ;;
      --poll-seconds) poll_seconds="$2" ;;
      *) usage ;;
    esac
    shift 2
  done
  [[ "${project}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{1,149}$ ]] || fail '--project must be a CodeBuild project name'
  [[ "${repository_uri}" =~ ${REPOSITORY_PATTERN} ]] || fail '--repository-uri must be an ECR repository URI'
  [[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || fail '--commit must be a full commit SHA'
  [[ "${build_date}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || fail '--build-date must be a UTC RFC 3339 time'
  [[ -n "${output}" ]] || fail '--output is required'
  [[ "${timeout_minutes}" =~ ^[0-9]+$ && "${timeout_minutes}" -ge 5 && "${timeout_minutes}" -le 120 ]] ||
    fail '--timeout-minutes must be between 5 and 120'
  [[ "${poll_seconds}" =~ ^[0-9]+$ && "${poll_seconds}" -ge 5 && "${poll_seconds}" -le 120 ]] ||
    fail '--poll-seconds must be between 5 and 120'
}

stop_unfinished_build() {
  if [[ -n "${build_id}" && "${completed}" != true ]]; then
    printf 'stopping unfinished build %s\n' "${build_id}" >&2
    aws codebuild stop-build --id "${build_id}" --query build.buildStatus --output text >&2 || true
  fi
}

start_build() {
  build_id="$(aws codebuild start-build \
    --project-name "${project}" \
    --source-version "${commit}" \
    --environment-variables-override \
    "name=EXPECTED_COMMIT,value=${commit},type=PLAINTEXT" \
    "name=BUILD_DATE,value=${build_date},type=PLAINTEXT" \
    --query build.id --output text)"
  [[ "${build_id}" =~ ^${project}:[0-9a-f-]{36}$ ]] || fail "CodeBuild returned an unexpected build ID: ${build_id}"
  printf 'started CodeBuild build %s for %s\n' "${build_id}" "${commit}"
}

describe_build() {
  local response
  response="$(aws codebuild batch-get-builds --ids "${build_id}" --output json)"
  jq -e --arg id "${build_id}" '.builds | length == 1 and .[0].id == $id' <<< "${response}" > /dev/null ||
    fail "CodeBuild does not report build ${build_id}"
  jq -c '.builds[0]' <<< "${response}"
}

wait_for_build() {
  local deadline phase last_phase='' build
  deadline=$(($(date +%s) + timeout_minutes * 60))
  while true; do
    build="$(describe_build)"
    phase="$(jq -r '.currentPhase' <<< "${build}")"
    if [[ "${phase}" != "${last_phase}" ]]; then
      printf '%s phase %s\n' "$(date -u +%H:%M:%SZ)" "${phase}"
      last_phase="${phase}"
    fi
    if jq -e '.buildComplete == true' <<< "${build}" > /dev/null; then
      completed=true
      final_build="${build}"
      return
    fi
    [[ "$(date +%s)" -lt "${deadline}" ]] || fail "build ${build_id} did not finish within ${timeout_minutes} minutes"
    sleep "${poll_seconds}"
  done
}

print_log_tail() {
  local build="$1" group stream
  group="$(jq -r '.logs.groupName // empty' <<< "${build}")"
  stream="$(jq -r '.logs.streamName // empty' <<< "${build}")"
  [[ -n "${group}" && -n "${stream}" ]] || return 0
  printf 'last build log lines (%s):\n' "${stream}" >&2
  aws logs get-log-events --log-group-name "${group}" --log-stream-name "${stream}" --limit 60 \
    --start-from-head false --query 'events[].message' --output text >&2 || true
}

exported() {
  local value
  value="$(jq -r --arg name "$2" '[.exportedEnvironmentVariables[]? | select(.name == $name) | .value] |
    if length == 1 then .[0] else "" end' <<< "$1")"
  [[ -n "${value}" ]] || fail "the build did not export $2 exactly once"
  printf '%s\n' "${value}"
}

verify_build() {
  local build="$1" status resolved
  status="$(jq -r '.buildStatus' <<< "${build}")"
  if [[ "${status}" != SUCCEEDED ]]; then
    print_log_tail "${build}"
    fail "build ${build_id} finished with status ${status}"
  fi
  resolved="$(jq -r '.resolvedSourceVersion' <<< "${build}")"
  [[ "${resolved}" == "${commit}" ]] || fail "CodeBuild built ${resolved}, expected ${commit}"
}

verify_staged_image() {
  local build="$1" digest tag reference number repository_name details
  number="$(jq -er '.buildNumber' <<< "${build}")"
  digest="$(exported "${build}" IMAGE_DIGEST)"
  tag="$(exported "${build}" IMAGE_TAG)"
  reference="$(exported "${build}" IMAGE_REFERENCE)"
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the build exported an invalid digest: ${digest}"
  [[ "${tag}" == "${commit}-${number}" ]] || fail "the build exported tag ${tag}, expected ${commit}-${number}"
  [[ "${reference}" == "${repository_uri}@${digest}" ]] ||
    fail "the build exported reference ${reference}, expected ${repository_uri}@${digest}"
  repository_name="${repository_uri#*/}"
  details="$(aws ecr describe-images --repository-name "${repository_name}" \
    --image-ids "imageDigest=${digest}" --output json)"
  jq -e --arg digest "${digest}" --arg tag "${tag}" --arg media "${IMAGE_MANIFEST}" '
    .imageDetails | length == 1 and
    (.[0].imageDigest == $digest) and
    (.[0].imageManifestMediaType == $media) and
    ((.[0].imageTags // []) | index($tag) != null)' <<< "${details}" > /dev/null ||
    fail "ECR does not hold ${digest} as a Docker v2 image manifest tagged ${tag}"
  mkdir -p "$(dirname "${output}")"
  jq -n \
    --arg commit "${commit}" \
    --arg build_id "${build_id}" \
    --argjson build_number "${number}" \
    --arg builder_image "$(jq -r '.environment.image' <<< "${build}")" \
    --arg buildah "$(exported "${build}" BUILDAH_VERSION)" \
    --arg repository "${repository_uri}" \
    --arg tag "${tag}" \
    --arg digest "${digest}" \
    --arg reference "${reference}" \
    --arg started "$(jq -r '.startTime' <<< "${build}")" \
    --arg ended "$(jq -r '.endTime' <<< "${build}")" \
    --arg pushed "$(jq -r '.imageDetails[0].imagePushedAt' <<< "${details}")" \
    --argjson size "$(jq '.imageDetails[0].imageSizeInBytes' <<< "${details}")" \
    '{commit: $commit, codebuild: {build_id: $build_id, build_number: $build_number, builder_image: $builder_image,
      buildah_version: $buildah, started: $started, ended: $ended},
      staging: {repository: $repository, tag: $tag, digest: $digest, reference: $reference, pushed: $pushed,
      size_bytes: $size}}' > "${output}"
  printf 'staged image %s\n' "${reference}"
}

main() {
  parse_arguments "$@"
  command -v aws > /dev/null || fail 'the AWS CLI is required'
  command -v jq > /dev/null || fail 'jq is required'
  trap stop_unfinished_build EXIT
  start_build
  wait_for_build
  verify_build "${final_build}"
  verify_staged_image "${final_build}"
}

main "$@"
