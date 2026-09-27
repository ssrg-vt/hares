#!/bin/bash
#
# run_offload_demo.sh - Single-machine Hares enclave-offloading demo.
#
# Runs two Hares monitor instances on localhost:
#   * SERVER (the "SGX node")  - actually executes the enclave (SGX simulation mode)
#   * CLIENT (the "non-SGX node") - runs the application and offloads every ecall
#     to the SERVER over TCP.
#
# Both monitors trace the SAME application binary. Because ASLR is disabled and
# the OE host binary is non-PIE, the two processes share an identical virtual
# address layout, which is what lets Hares synchronise memory pages and redirect
# control flow between them.
#
# This is the "scaled-down demonstration" of the paper's two-node setup: instead
# of two physical machines it uses two processes / two containers on one host,
# and it runs the enclave in SGX *simulation* mode so that no SGX hardware is
# required. See artifact/README.md.
#
# Usage:  run_offload_demo.sh [APP_DIR]
#   APP_DIR   directory containing config.json and the app (default: the
#             prebuilt OE helloworld under artifact/apps/helloworld)
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
APP_DIR="${1:-$REPO_ROOT/artifact/apps/helloworld}"
MONITOR="${MONITOR:-$(command -v hares_monitor || echo "$REPO_ROOT/bin/hares_monitor")}"

# TCP ports for the localhost client<->server channel.
SERVER_LISTEN_PORT="${SERVER_LISTEN_PORT:-12001}"
OTHER_PORT="${OTHER_PORT:-12000}"
SERVER_IP="${SERVER_IP:-127.0.0.1}"

LOG_DIR="${LOG_DIR:-$APP_DIR/logs}"
mkdir -p "$LOG_DIR"
SERVER_LOG="$LOG_DIR/server.log"
CLIENT_LOG="$LOG_DIR/client.log"

die() { echo "ERROR: $*" >&2; exit 1; }

# Use sudo only when not already root (containers run as root and may lack sudo).
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

[ -x "$MONITOR" ]        || die "monitor not found/executable: $MONITOR (build it or set \$MONITOR)"
[ -f "$APP_DIR/config.json" ] || die "no config.json in APP_DIR=$APP_DIR"

echo "=================================================================="
echo " Hares single-machine enclave-offloading demo"
echo "   monitor : $MONITOR"
echo "   app dir : $APP_DIR"
echo "   channel : client -> ${SERVER_IP}:${SERVER_LISTEN_PORT} (server listens)"
echo "=================================================================="

# ------------------------------------------------------------------
# 1. ASLR must be OFF: the config.json breakpoint addresses are absolute
#    addresses in a non-PIE binary, and both nodes must share one layout.
# ------------------------------------------------------------------
ASLR="$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo '?')"
ASLR_CHANGED=0
if [ "$ASLR" != "0" ]; then
  echo "[*] Disabling ASLR (was: $ASLR) ..."
  echo 0 | $SUDO tee /proc/sys/kernel/randomize_va_space >/dev/null \
      || die "could not disable ASLR (need root / --privileged container)"
  ASLR_CHANGED=1
  # Note: /proc/sys/kernel/randomize_va_space is NOT namespaced, so in a
  # --privileged container this also disables ASLR on the host. See the note
  # printed at the end for how to restore it.
fi

# ------------------------------------------------------------------
# 2. Optionally source the Open Enclave environment (for OE host binaries).
# ------------------------------------------------------------------
if [ -f /opt/openenclave/share/openenclave/openenclaverc ]; then
  # shellcheck disable=SC1091
  source /opt/openenclave/share/openenclave/openenclaverc
fi

cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
  # Reap any monitor left behind. Match the process name EXACTLY (-x, against the
  # binary name only) so this never matches an unrelated shell/command that merely
  # mentions "hares_monitor" on its command line.
  pkill -x hares_monitor 2>/dev/null
}
trap cleanup EXIT

cd "$APP_DIR" || die "cannot cd to $APP_DIR"

# ------------------------------------------------------------------
# 3. Launch the SERVER (SGX node) - it waits for the client to connect.
# ------------------------------------------------------------------
echo "[*] Starting SERVER monitor  -> $SERVER_LOG"
"$MONITOR" -m server -c ./config.json -p "$OTHER_PORT" -t "$SERVER_LISTEN_PORT" \
    >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait until the server is actually listening (or died).
for _ in $(seq 1 50); do
  if grep -qiE 'waiting for connections|Setting up the node as server' "$SERVER_LOG" 2>/dev/null; then break; fi
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "---- server.log ----"; cat "$SERVER_LOG"; die "server exited early"; }
  sleep 0.2
done

# ------------------------------------------------------------------
# 4. Launch the CLIENT (non-SGX node) - it offloads ecalls to the server.
# ------------------------------------------------------------------
echo "[*] Starting CLIENT monitor  -> $CLIENT_LOG"
"$MONITOR" -m client -c ./config.json -r "$SERVER_IP" -p "$SERVER_LISTEN_PORT" -t "$OTHER_PORT" \
    >"$CLIENT_LOG" 2>&1
CLIENT_RC=$?

# The client exits cleanly once the offloaded enclave call completes. The server
# ("SGX node") is designed to stay up to serve further offloads, so we stop it
# now rather than waiting for it to exit on its own.
sleep 1
kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
SERVER_PID=""

echo ""
echo "=================================================================="
echo " RESULT"
echo "=================================================================="
DISPLAY_RE='hello world|simulation mode|enclave called|^Enclave:|encrypt|decrypt|seal|unseal'
echo "--- enclave / offload output (server side) --------------------"
grep -iE "$DISPLAY_RE" "$SERVER_LOG" | head -12 || echo "(none on server)"
echo "--- enclave / offload output (client side) --------------------"
grep -iE "$DISPLAY_RE" "$CLIENT_LOG" | head -12 || echo "(none on client)"
echo "--- client exit code: $CLIENT_RC ------------------------------"
echo ""
echo "Full logs: $SERVER_LOG , $CLIENT_LOG"

if [ "$ASLR_CHANGED" = "1" ]; then
  echo ""
  echo "NOTE: ASLR was disabled system-wide (this setting is not namespaced, so"
  echo "      a --privileged container also affects the host). Restore it with:"
  echo "        sudo sysctl -w kernel.randomize_va_space=$ASLR"
fi

# Success = the client (non-SGX node) drove the whole application to completion
# with its ecalls executed remotely on the server. A clean client exit (rc 0)
# means every offloaded enclave transition returned correctly.
if [ "$CLIENT_RC" -eq 0 ]; then
  echo "DEMO_RESULT: SUCCESS (offloaded run completed; client exit 0)"
  exit 0
else
  echo "DEMO_RESULT: FAILED (client exit $CLIENT_RC - see the logs above)"
  exit 1
fi
