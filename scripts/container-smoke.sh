#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
IMAGE="${1:-crowdshield:local}"

case "$IMAGE" in
  ""|*[!A-Za-z0-9._:/@-]*)
    printf 'invalid image reference\n' >&2
    exit 2
    ;;
esac

docker image inspect "$IMAGE" >/dev/null
mkdir -p .tmp
WORK="$(mktemp -d "$ROOT/.tmp/container-smoke.XXXXXXXX")"
SUFFIX="${WORK##*.}"
NETWORK="crowdshield-smoke-${SUFFIX,,}"
APP="crowdshield-smoke-app-${SUFFIX,,}"
MOCK="crowdshield-smoke-lapi-${SUFFIX,,}"
MOCK_IMAGE="crowdshield-mock-lapi:${SUFFIX,,}"
RUNTIME_UID="$(id -u)"
RUNTIME_GID="$(id -g)"
CONFIG="$WORK/crowdshield.yaml"
CREDENTIALS="$WORK/lapi-credentials.yaml"
DATA="$WORK/data"

cleanup() {
  docker rm -f "$APP" "$MOCK" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker image rm "$MOCK_IMAGE" >/dev/null 2>&1 || true
  rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'container smoke test failed: %s\n' "$1" >&2
  exit 1
}

expect_exit() {
  local expected="$1" label="$2"
  shift 2
  local stdout="$WORK/${label}.stdout" stderr="$WORK/${label}.stderr" status
  set +e
  "$@" >"$stdout" 2>"$stderr"
  status=$?
  set -e
  [[ "$status" == "$expected" ]] || fail "$label returned $status, expected $expected"
  [[ "$(<"$stdout")" != *mock-password* && "$(<"$stderr")" != *mock-password* ]] || fail "$label disclosed a synthetic credential"
}

install -m 0444 test/container/crowdshield.smoke.yaml "$CONFIG"
printf '%s\n' \
  'url: http://mock-lapi:8080' \
  'login: crowdshield-test' \
  'password: mock-password' >"$CREDENTIALS"
chmod 0600 "$CREDENTIALS"
mkdir -m 0700 "$DATA"
[[ -f "$CREDENTIALS" && ! -L "$CREDENTIALS" ]] || fail 'credential fixture is not a regular non-symlink file'
[[ "$(stat -c '%u:%g:%a' "$CREDENTIALS")" == "$RUNTIME_UID:$RUNTIME_GID:600" ]] || fail 'credential fixture ownership or mode is wrong'
[[ "$(stat -c '%u:%g:%a' "$DATA")" == "$RUNTIME_UID:$RUNTIME_GID:700" ]] || fail 'data directory ownership or mode is wrong'
read -r CONFIG_HASH _ < <(sha256sum "$CONFIG")
read -r CREDENTIAL_HASH _ < <(sha256sum "$CREDENTIALS")

VERSION_OUTPUT="$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true "$IMAGE" version)"
[[ "$VERSION_OUTPUT" == *'crowdshield '* ]] || fail 'version command output is missing'
HELP_OUTPUT="$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true "$IMAGE" help)"
[[ "$HELP_OUTPUT" == *healthcheck* ]] || fail 'help does not list healthcheck'

docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --user "$RUNTIME_UID:$RUNTIME_GID" \
  --mount "type=bind,src=$CONFIG,dst=/config/crowdshield.yaml,readonly" \
  --mount "type=bind,src=$CREDENTIALS,dst=/run/secrets/crowdshield-lapi-credentials.yaml,readonly" \
  "$IMAGE" validate-config >/dev/null

expect_exit 2 unknown-command docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true "$IMAGE" definitely-not-a-command
expect_exit 2 missing-config docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true "$IMAGE" run
expect_exit 1 missing-credential docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --user "$RUNTIME_UID:$RUNTIME_GID" \
  --mount "type=bind,src=$CONFIG,dst=/config/crowdshield.yaml,readonly" \
  --mount "type=bind,src=$DATA,dst=/data" "$IMAGE" run

chmod 0640 "$CREDENTIALS"
expect_exit 1 invalid-credential-mode docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --user "$RUNTIME_UID:$RUNTIME_GID" \
  --mount "type=bind,src=$CONFIG,dst=/config/crowdshield.yaml,readonly" \
  --mount "type=bind,src=$CREDENTIALS,dst=/run/secrets/crowdshield-lapi-credentials.yaml,readonly" \
  --mount "type=bind,src=$DATA,dst=/data" "$IMAGE" run
chmod 0600 "$CREDENTIALS"

expect_exit 127 no-shell docker run --rm --network none --read-only --entrypoint /bin/sh "$IMAGE"

# The mock image is a separate scratch-only test artifact. It is never copied
# into the production image and is removed by the cleanup trap.
docker buildx build --platform linux/amd64 --load --progress=plain \
  --file test/container/mock-lapi.Dockerfile --tag "$MOCK_IMAGE" . >/dev/null

docker network create --driver bridge --internal "$NETWORK" >/dev/null
docker run --detach --name "$MOCK" --network "$NETWORK" --network-alias mock-lapi \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 \
  "$MOCK_IMAGE" >/dev/null

for _ in {1..100}; do
  [[ "$(docker logs "$MOCK" 2>&1)" == *'mock-lapi ready'* ]] && break
  [[ "$(docker inspect --format '{{.State.Running}}' "$MOCK")" == true ]] || fail 'mock LAPI exited before readiness'
  sleep 0.1
done
[[ "$(docker logs "$MOCK" 2>&1)" == *'mock-lapi ready'* ]] || fail 'mock LAPI readiness timed out'

docker create --name "$APP" --network "$NETWORK" --network-alias crowdshield \
  --user "$RUNTIME_UID:$RUNTIME_GID" --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 128 --stop-timeout 15 \
  --mount "type=bind,src=$CONFIG,dst=/config/crowdshield.yaml,readonly" \
  --mount "type=bind,src=$CREDENTIALS,dst=/run/secrets/crowdshield-lapi-credentials.yaml,readonly" \
  --mount "type=bind,src=$DATA,dst=/data" "$IMAGE" run >/dev/null
docker start "$APP" >/dev/null

ROOT_DIFF_BASELINE="$(docker diff "$APP")"
declare -A EXPECTED_ROOT_DIFF=(
  ["A /config"]=1
  ["A /config/crowdshield.yaml"]=1
  ["C /run"]=1
  ["A /run/secrets"]=1
  ["A /run/secrets/crowdshield-lapi-credentials.yaml"]=1
)
declare -A OBSERVED_ROOT_DIFF=()
while IFS= read -r entry; do
  [[ -n "$entry" ]] || continue
  [[ -n "${EXPECTED_ROOT_DIFF[$entry]+present}" ]] || fail "unexpected Docker mount preparation entry: $entry"
  OBSERVED_ROOT_DIFF["$entry"]=1
done <<<"$ROOT_DIFF_BASELINE"
[[ "${#OBSERVED_ROOT_DIFF[@]}" == "${#EXPECTED_ROOT_DIFF[@]}" ]] || fail 'Docker mount preparation baseline is incomplete'

HEALTH=''
for _ in {1..150}; do
  RUNNING="$(docker inspect --format '{{.State.Running}}' "$APP")"
  [[ "$RUNNING" == true ]] || fail 'Crowdshield exited before becoming healthy'
  HEALTH="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$APP")"
  [[ "$HEALTH" == healthy ]] && break
  [[ "$HEALTH" != unhealthy ]] || fail 'Docker healthcheck reported unhealthy'
  sleep 0.2
done
[[ "$HEALTH" == healthy ]] || fail 'Docker healthcheck timed out'

docker exec "$APP" /crowdshield healthcheck --timeout 1s
[[ "$(docker inspect --format '{{.Config.User}}' "$APP")" == "$RUNTIME_UID:$RUNTIME_GID" ]] || fail 'running container identity is not the requested numeric UID/GID'
[[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$APP")" == true ]] || fail 'root filesystem is not read-only'
MOUNTS="$(docker inspect --format '{{range .Mounts}}{{println .Destination .RW}}{{end}}' "$APP")"
[[ "$MOUNTS" == *'/config/crowdshield.yaml false'* ]] || fail 'configuration mount is not read-only'
[[ "$MOUNTS" == *'/run/secrets/crowdshield-lapi-credentials.yaml false'* ]] || fail 'credential mount is not read-only'
[[ "$MOUNTS" == *'/data true'* ]] || fail 'data mount is not writable'
[[ -f "$DATA/crowdshield.db" ]] || fail 'daemon did not create persistent SQLite state in /data'
[[ "$(stat -c '%u:%g' "$DATA/crowdshield.db")" == "$RUNTIME_UID:$RUNTIME_GID" ]] || fail 'SQLite state ownership does not match runtime identity'
ROOT_DIFF="$(docker diff "$APP")"
declare -A OBSERVED_ROOT_DIFF_LIVE=()
while IFS= read -r entry; do
  [[ -n "$entry" ]] || continue
  [[ -n "${EXPECTED_ROOT_DIFF[$entry]+present}" ]] || fail "daemon changed an unexpected root-layer path: $entry"
  OBSERVED_ROOT_DIFF_LIVE["$entry"]=1
done <<<"$ROOT_DIFF"
[[ "${#OBSERVED_ROOT_DIFF_LIVE[@]}" == "${#EXPECTED_ROOT_DIFF[@]}" ]] || fail 'daemon changed the Docker bind-target root-layer set'

read -r CONFIG_HASH_AFTER _ < <(sha256sum "$CONFIG")
read -r CREDENTIAL_HASH_AFTER _ < <(sha256sum "$CREDENTIALS")
[[ "$CONFIG_HASH_AFTER" == "$CONFIG_HASH" && "$CREDENTIAL_HASH_AFTER" == "$CREDENTIAL_HASH" ]] || fail 'read-only input file changed'
[[ "$(stat -c '%a' "$CREDENTIALS")" == 600 ]] || fail 'credential mode changed'

docker stop --time 15 "$APP" >/dev/null
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$APP")" == 0 ]] || fail 'SIGTERM did not produce a clean exit'
[[ "$(docker inspect --format '{{.State.OOMKilled}}' "$APP")" == false ]] || fail 'container was OOM-killed'

docker stop --time 5 "$MOCK" >/dev/null
printf 'container smoke tests passed: isolated internal network, synthetic LAPI, read-only root, UID/GID %s:%s, writable /data, healthy liveness, clean SIGTERM\n' "$RUNTIME_UID" "$RUNTIME_GID"
