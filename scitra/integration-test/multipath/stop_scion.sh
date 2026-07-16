#!/bin/bash

set -e

if [ -z "$SCION_ROOT" ]; then
  echo "SCION_ROOT is not set"
  exit 1
fi

(cd "$SCION_ROOT" && sudo tools/supervisor.sh stop all && sudo tools/supervisor.sh shutdown)
