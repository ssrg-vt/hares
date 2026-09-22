#!/bin/bash
#
# demo.sh - run the single-machine enclave-offloading demo inside the image.
#
# Starts a --privileged `hares:latest` container (needed for ptrace / userfaultfd
# / disabling ASLR) and runs the offload demo with the prebuilt Open Enclave
# helloworld sample in SGX *simulation* mode. No SGX hardware is required.
#
# Optional: if the host has SGX and you built enclaves in hardware mode, pass
#   HW=1  to additionally map /dev/sgx_enclave into the container.
#
set -euo pipefail

# Usage: demo.sh [app-name]     (app-name is a directory under artifact/apps/,
#                                default: helloworld; also try: file-encryptor)
IMAGE="${IMAGE:-hares:latest}"
APP_NAME="${1:-helloworld}"
APP="${APP:-/opt/hares/artifact/apps/$APP_NAME}"

docker_args=(--rm --privileged)
if [ "${HW:-0}" = "1" ] && [ -e /dev/sgx_enclave ]; then
  echo "[*] HW=1: mapping /dev/sgx_enclave into the container"
  docker_args+=(--device /dev/sgx_enclave)
fi

echo "[*] Launching demo in $IMAGE ..."
docker run "${docker_args[@]}" "$IMAGE" \
  bash /opt/hares/artifact/scripts/run_offload_demo.sh "$APP"
