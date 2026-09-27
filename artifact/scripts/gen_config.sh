#!/bin/bash
#
# gen_config.sh - generate a Hares config.json for an Open Enclave host binary.
#
# Hares intercepts enclave transitions by setting ptrace breakpoints at the
# call sites of: enclave creation (oe_create_*_enclave), every ecall wrapper
# (the trusted functions declared in the .edl), and enclave teardown
# (oe_terminate_enclave). For each such call it needs a *pair* of addresses:
# the call instruction itself and the instruction right after it returns.
#
# This script derives those addresses from the (non-PIE) host binary with
# objdump, so a config stays correct after the application is rebuilt.
#
# Usage:
#   gen_config.sh <host_binary> <app.edl> "<user_args_json_array>" [--simulate]
#
# Example:
#   gen_config.sh host/datasealinghost datasealing.edl \
#       '"host/host","./enclave_a_v1/enclave.signed","enclave_a_v2/enclave.signed","enclave_b/enclave.signed"' \
#       --simulate > config.json
#
set -u

HOST_BIN="${1:?usage: gen_config.sh <host_binary> <app.edl> <user_args_json> [--simulate]}"
EDL="${2:?missing .edl file}"
USER_ARGS_INNER="${3:?missing user_args JSON array contents}"
SIMULATE="${4:-}"

command -v objdump >/dev/null || { echo "objdump not found (install binutils)" >&2; exit 1; }

if [ "$(readelf -h "$HOST_BIN" 2>/dev/null | awk '/Type:/{print $2}')" != "EXEC" ]; then
  echo "WARNING: $HOST_BIN is not a non-PIE EXEC; breakpoint addresses will not be" >&2
  echo "         stable under ASLR. Rebuild the host as non-PIE." >&2
fi

DIS="$(objdump -d "$HOST_BIN")"

# 1. main address
MAIN_ADDR="0x$(printf '%s\n' "$DIS" | awk '/<main>:/{print $1; exit}')"

# 2. ecall names from the .edl trusted{} block (strip comments first)
ECALLS="$(sed 's://.*::' "$EDL" \
  | awk '/^[[:space:]]*trusted[[:space:]]*\{/{t=1} t && /}/{t=0} t' \
  | grep -oE '[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(' \
  | sed 's/[[:space:]]*(//' \
  | grep -vE '^(public|trusted|untrusted)$' | sort -u)"

# 3. every call whose target we care about: oe_create_*_enclave,
#    oe_terminate_enclave, or one of the ecall wrappers. OE names the host-side
#    ecall wrapper "<enclave>_<ecall>", so we match a target symbol that is, or
#    ends with "_", the ecall name.
ecall_alt=""
for e in $ECALLS; do ecall_alt="${ecall_alt:+$ecall_alt|}$e"; done
# A target <symbol> matches when it is oe_create_*_enclave, oe_terminate_enclave,
# or ends with one of the ecall names (optionally prefixed by "<enclave>_").
targets_regex="oe_create_[A-Za-z0-9_]*_enclave|oe_terminate_enclave"
[ -n "$ecall_alt" ] && targets_regex="$targets_regex|([A-Za-z0-9_]+_)?($ecall_alt)"

# Walk the disassembly; when a line is a `call ... <TARGET>` emit the call
# address and the following instruction address as a breakpoint pair.
BPS="$(printf '%s\n' "$DIS" | awk -v re="$targets_regex" '
  /^[[:space:]]*[0-9a-f]+:/ {
    addr=$1; sub(":","",addr);
    if (prev_is_target) { print "0x" prev_addr; print "0x" addr; prev_is_target=0 }
    if ($0 ~ /[[:space:]]call[[:space:]]/ && $0 ~ ("<(" re ")([+@][^>]*)?>[[:space:]]*$")) {
      prev_is_target=1; prev_addr=addr
    } else { prev_is_target=0 }
  }')"

# Emit JSON
{
  echo "{"
  echo "  \"main_address\":\"$MAIN_ADDR\","
  if [ -n "$SIMULATE" ]; then
    echo "  \"user_args\": [$USER_ARGS_INNER, \"--simulate\", null],"
  else
    echo "  \"user_args\": [$USER_ARGS_INNER, null],"
  fi
  printf '  "breakpoints": ['
  first=1
  while read -r b; do
    [ -z "$b" ] && continue
    if [ $first -eq 1 ]; then printf '"%s"' "$b"; first=0; else printf ', "%s"' "$b"; fi
  done <<< "$BPS"
  echo "]"
  echo "}"
}
