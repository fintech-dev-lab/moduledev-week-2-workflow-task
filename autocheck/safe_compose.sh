#!/usr/bin/env bash
set -euo pipefail

home="${HOME:-/tmp}"
path="${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
docker_config="${DOCKER_CONFIG:-$home/.docker}"
docker_host="${DOCKER_HOST:-}"
docker_context="${DOCKER_CONTEXT:-}"
gateway_port="${COURSE_GATEWAY_PORT:-8080}"
test_profile="${COURSE_TEST_PROFILE:-1}"
failpoint="${COURSE_FAILPOINT:-}"

# Admission checks inspect the declared 8080 contract, while runtime uses a free host port.
for argument in "$@"; do
  if [[ "$argument" == "config" ]]; then
    gateway_port=8080
    break
  fi
done

exec env -i \
  PATH="$path" \
  HOME="$home" \
  DOCKER_CONFIG="$docker_config" \
  DOCKER_HOST="$docker_host" \
  DOCKER_CONTEXT="$docker_context" \
  COURSE_GATEWAY_PORT="$gateway_port" \
  COURSE_TEST_PROFILE="$test_profile" \
  COURSE_FAILPOINT="$failpoint" \
  COMPOSE_DISABLE_ENV_FILE=1 \
  docker compose "$@"
