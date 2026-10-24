#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
image='python:3.14-slim-bookworm@sha256:945c2676dc2b18e0c1f16879244122c57c0ffede60006bf3df159c507a31bcae'
binary=${1:?Pass an explicit trusted copy of the existing qualified Linux Caddy binary}
docker image inspect "$image" >/dev/null
MSYS_NO_PATHCONV=1 docker run --rm --pull=never --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,nosuid,size=64m -e PYTHONDONTWRITEBYTECODE=1 -e QA_ASSERT_NO_NETWORK=1 \
  --mount "type=bind,src=$here,dst=/qa,readonly" --mount "type=bind,src=$binary,dst=/binary/caddy,readonly" \
  "$image" python /qa/validate.py --caddy /binary/caddy
