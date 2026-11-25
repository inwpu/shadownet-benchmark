#!/bin/sh
set -e
if [ -f /answers/flag41 ]; then
  MINIO_ROOT_PASSWORD="$(cat /answers/flag41)"
  export MINIO_ROOT_PASSWORD
fi
exec /opt/bin/docker-entrypoint.sh "$@"
