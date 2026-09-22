#!/bin/bash
#
# build_image.sh - build the Hares artifact-evaluation Docker image.
#
# Produces the image `hares:latest` (override with $IMAGE) containing:
#   * CRIU 3.16.1 (compel) built from source,
#   * the Hares monitor (hares_monitor) built from src/,
#   * the Open Enclave runtime for the simulation-mode sample enclave.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
IMAGE="${IMAGE:-hares:latest}"

cd "$REPO_ROOT"
echo "[*] Building $IMAGE from $REPO_ROOT ..."
docker build -f artifact/docker/Dockerfile -t "$IMAGE" .
echo "[*] Done. Image: $IMAGE"
echo "    Next: bash artifact/scripts/demo.sh"
