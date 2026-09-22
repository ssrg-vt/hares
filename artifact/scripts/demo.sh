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

IMAGE="${IMAGE:-hares:latest}"
APP="${APP:-/opt/hares/artifact/apps/helloworld}"

docker_args=(--rm --privileged)
if [ "${HW:-0}" = "1" ] && [ -e /dev/sgx_enclave ]; then
  echo "[*] HW=1: mapping /dev/sgx_enclave into the container"
  docker_args+=(--device /dev/sgx_enclave)
fi

echo "[*] Launching demo in $IMAGE ..."
docker run "${docker_args[@]}" "$IMAGE" \
  bash /opt/hares/artifact/scripts/run_offload_demo.sh "$APP"
