<!--
  Hares - Artifact Evaluation guide (Middleware 2026)
-->
# Hares — Artifact Evaluation

**Paper:** *Hares: A Framework for Transparent and Cross-Architecture Enclave Offloading* (Middleware 2026)

This directory contains everything needed to build, run, and reproduce the core
results of Hares. It is written so that a reviewer can go from a clean machine to
a working enclave-offloading demonstration **without any SGX hardware**, using
Open Enclave / Intel SGX *simulation mode* inside a Docker container.

---

## 1. Badges requested

| Badge | Requested | How this artifact supports it |
|-------|:---------:|-------------------------------|
| **Artifacts Available**  | ✅ | Public repository: <https://github.com/ssrg-vt/hares> |
| **Artifacts Functional** | ✅ | One-command Docker build of the Hares monitor + CRIU/compel; a scripted end-to-end enclave-offload demo (§4). |
| **Results Reproduced**   | ✅ (scaled) | The offloading mechanism and the per-application behaviour behind Figures 5–9 / Tables 3–4 can be reproduced in simulation mode; full-scale numbers need the two-node SGX testbed described in §6. |

Hares evaluates a *hardware* feature (Intel SGX). Per the Middleware AE guidance
for specialized hardware, this artifact provides a **scaled-down demonstration**
that runs on any x86-64 Linux host (no SGX required) and, optionally, a
**hardware mode** for machines that do have SGX.

---

## 2. What Hares is (one paragraph)

Hares lets a device that has **no** trusted execution environment (or a different
ISA) run a security-sensitive workload inside a **remote** Intel SGX enclave.
A userspace **monitor** (`hares_monitor`) runs on each node. On the client
(non-SGX) node it launches the application, intercepts every `ecall` with
`ptrace` breakpoints, and offloads enclave execution to the server (SGX) node;
a userspace distributed-shared-memory layer built on `userfaultfd` and
CRIU/`compel` parasite injection keeps the two address spaces coherent using a
simple MSI protocol. The paper describes two modes: a *binary-compatible* mode
for unmodified Intel SGX SDK binaries (x86↔x86) and an *RPC* mode built on an
extended Open Enclave SDK for cross-architecture offloading (e.g. ARM64→x86).

---

## 3. Repository layout (relevant parts)

```
hares/
├── src/            # the Hares monitor (hares_monitor) — ~3.3k LoC C
├── inc/            # monitor headers (+ generated parasite.h)
├── parasite_src/   # compel parasite injected into the traced application
├── Makefile        # builds the monitor (needs CRIU/compel + libcjson)
├── oeedger8r-cpp/  # extended Open Enclave edger8r (RPC-mode cross-arch stubs)
├── oe-sdk-aarch64/ # prebuilt Open Enclave SDK for ARM64 (RPC mode)
├── kernel/         # optional custom 5.15 kernel (.deb) used on the SGX node
├── tests/          # SGX / Open Enclave applications used in the evaluation
└── artifact/       # ← THIS AE package
    ├── README.md            # this file
    ├── docker/Dockerfile    # Ubuntu 20.04 + CRIU 3.16.1 + monitor + OE runtime
    ├── apps/helloworld/     # prebuilt OE sample (simulation mode) for the demo
    └── scripts/             # build + run helpers
```

---

## 4. Quick start (kick-the-tires, ~10–20 min, **no SGX needed**)

### 4.1 Requirements
- x86-64 Linux host with **Docker**.
- Ability to run a `--privileged` container (Hares needs `ptrace`, `userfaultfd`,
  and to disable ASLR). No SGX driver or hardware is required for this path.

> **Side effect:** the demo disables ASLR (`kernel.randomize_va_space=0`). This
> knob is not namespaced, so a `--privileged` container changes it on the host
> too. The demo prints the exact command to restore it
> (`sudo sysctl -w kernel.randomize_va_space=2`).

### 4.2 Build the image
From the repository root:
```bash
bash artifact/scripts/build_image.sh
# equivalently:
#   docker build -f artifact/docker/Dockerfile -t hares:latest .
```
This produces `hares:latest` containing CRIU 3.16.1, the freshly built
`hares_monitor`, and the Open Enclave runtime.

### 4.3 Run the enclave-offloading demo
```bash
bash artifact/scripts/demo.sh                 # helloworld (default)
bash artifact/scripts/demo.sh file-encryptor  # a real mbedTLS crypto app
```
`demo.sh` starts a `--privileged` `hares:latest` container and, inside it, runs
`run_offload_demo.sh`, which launches two monitors on localhost:

- a **server** ("SGX node") that actually executes the enclave in **simulation mode**;
- a **client** ("non-SGX node") that runs the application and offloads each ecall.

Two applications are prebuilt for the no-hardware demo:
`helloworld` (minimal) and `file-encryptor` (one of the paper's evaluation apps,
Figures 6/8/9 — it encrypts and then decrypts a file entirely inside the remote
enclave using mbedTLS).

### 4.4 Expected result
The output is **split across the two nodes**, which is exactly what enclave
offloading looks like:

```
==================================================================
 RESULT
==================================================================
--- enclave / offload output (server side) --------------------
Hello world from the enclave                <-- the ENCLAVE ran on the SGX server
--- enclave / offload output (client side) --------------------
Running in simulation mode                  <-- host startup, on the client
Enclave called into host to print: Hello World!   <-- the ocall, back on the client
--- client exit code: 0 ------------------------------
DEMO_RESULT: SUCCESS (enclave executed via offload)
```

The enclave's own message (`Hello world from the enclave`) is produced on the
**server** ("SGX node"), because that is where the `ecall` was executed after the
client offloaded it. The host-side message and the `ocall` result appear on the
**client** ("non-SGX node"). The client never runs the enclave locally — it only
intercepts the ecalls (at the `config.json` breakpoints) and ships them to the
server, which is the whole point of Hares.

> *Interpreting it:* the client monitor sets breakpoints at the three ecall sites
> from `config.json` (enclave creation, the `helloworld` ecall, enclave
> termination) and, at each one, synchronises the VMAs/registers and asks the
> server to run that region. The client exits cleanly (`rc=0`) once the offloaded
> call returns; the server node is designed to stay up for further offloads, so
> the demo stops it explicitly at the end.

---

## 5. Reproducing the paper's applications

The paper evaluates six applications in two modes. All can be exercised in
simulation mode; the *numbers* in the paper come from the two-node hardware
testbed (§6).

### 5.1 RPC mode — Open Enclave applications
`file-encryptor` and `data-sealing` (Figures 6–9) plus `helloworld`,
`log_callback`, `debugmalloc`. Each application ships a `config.json` giving its
`main` address and the ecall breakpoint pairs the monitor intercepts. To offload
an application:
```bash
# inside the container, from any application directory containing config.json
bash /opt/hares/artifact/scripts/run_offload_demo.sh /path/to/<app>
```

`helloworld` and `file-encryptor` are **prebuilt for simulation mode** and are
verified end-to-end by `demo.sh` (§4). The other OE apps live under `tests/`;
their prebuilt hosts were compiled for hardware mode. To run one of them without
SGX, rebuild the host with the Open Enclave SDK image (`Dockerfile.full`, §7),
enabling `OE_ENCLAVE_FLAG_SIMULATE` in the `oe_create_*_enclave` call, then
regenerate the `config.json` breakpoints from the rebuilt binary:

```bash
# derive main + ecall breakpoint pairs directly from the (non-PIE) host binary
bash artifact/scripts/gen_config.sh <host_binary> <app.edl> \
     '"<argv0>","<arg1>",...'  > config.json
```
`gen_config.sh` reads the ecall names from the `.edl` and finds every
`oe_create_*_enclave`, ecall-wrapper, and `oe_terminate_enclave` call site with
`objdump`; it reproduces the shipped `helloworld`/`file-encryptor` configs
exactly, so a config stays correct across rebuilds.

**data-sealing** (Figures 6–9) is a three-enclave application. We verified that
it **builds in simulation mode** with `Dockerfile.full` and **runs standalone on
real SGX** (this machine seals/unseals across three enclaves successfully):
```bash
# inside a `hares:full` container, with tests/ mounted at /mnt/tests
source /opt/openenclave/share/openenclave/openenclaverc
cp -r /mnt/tests/data-sealing /tmp/ds && : > /tmp/config.mk && cd /tmp/ds
# (simulation build) enable the SIMULATE flag, then build with clang:
sed -i 's/OE_ENCLAVE_FLAG_DEBUG,/OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE,/' host/host.cpp
make build CC=clang-11 CXX=clang++-11 C_COMPILER=clang CXX_COMPILER=clang++
# (hardware run on real SGX) drop the sed patch and pass --device /dev/sgx_enclave:
./host/host ./enclave_a_v1/enclave.signed ./enclave_a_v2/enclave.signed ./enclave_b/enclave.signed
```
Its full *offloaded* run is exercised as part of the two-node hardware
evaluation (§6); on a single host the multi-enclave offload is sensitive to the
loopback timing, so we recommend the two-node setup for data-sealing.

### 5.2 Binary-compatible mode — Intel SGX SDK applications
`bw-mem`, `lat-rand` (the `lmbench` micro-benchmarks), the empty-ecall
`microbench` (Figure 5), `sgx-dnet`, and `plinius`. These build with the Intel
SGX SDK (`SGX_MODE=SIM` for the no-hardware path, `SGX_MODE=HW` on an SGX host).
Their sources live under `tests/`.

### 5.3 Mapping to paper claims

| Paper item | Application(s) | What it shows | Reproducible here |
|------------|----------------|---------------|-------------------|
| Fig. 5 | `microbench` | Raw offload overhead vs. #ecalls | Mechanism (sim) |
| Fig. 6 / Tab. 4 | SGX-DNet, Plinius, bw-mem, lat-rand, File-Enc, Data-Sealing | End-to-end overhead vs. native | Behaviour (sim); numbers need testbed |
| Fig. 7 | all six | Event profile (migrations, pages, ptrace, …) | Behaviour (sim) |
| Fig. 8–9 / Tab. 3 | File-Enc, Data-Sealing, Debug-malloc, log-callback, Attestation | RPC-mode overhead breakdown | Behaviour (sim); numbers need testbed |

---

## 6. Full hardware reproduction (two-node SGX testbed)

The paper's measured numbers were produced on the environment in Table 2:

- **Client / non-SGX node:** Raspberry Pi 4b (ARM Cortex-A53) *or* an x86 node
  without SGX (edge/IoT setup), or a second x86 node (cloud setup).
- **Server / SGX node:** Intel Core i7-9700 laptop/desktop (edge) or Intel Xeon
  P-8370C (cloud), running Ubuntu 20.04, Linux 5.15, with SGX enabled.
- Applications run inside **Docker containers** (Ubuntu 20.04 base) on both nodes.
- Interconnect: 1 GbE (edge, ~1.7 ms RTT) / 10 GbE Infiniband (cloud, ~0.15 ms RTT).

To run on real SGX hardware, install the Intel SGX PSW/DCAP stack (and the
Open Enclave SDK for RPC mode), build the applications in `SGX_MODE=HW`
(Intel) / hardware mode (OE), and run the two monitors on the two nodes with the
server's real IP instead of `127.0.0.1`. The per-application `config.json`
files and the `tests/qemu_sim/test/test_monitor_mode_*.sh` scripts document the
exact invocations.

If your host has SGX (check with `ls /dev/sgx_enclave` and `grep -o sgx
/proc/cpuinfo | head -1`), you can pass the device into the container
(`--device /dev/sgx_enclave`) and drop `--simulate` to run enclaves on real
hardware.

---

## 7. Building applications from source (Open Enclave SDK)

`artifact/apps/helloworld` ships **prebuilt** simulation-mode binaries so the
kick-the-tires demo needs no SDK. To rebuild the OE applications (or the other
OE apps under `tests/`) from source, use the extended SDK image described in
`artifact/docker/Dockerfile.full`, which additionally installs the Open Enclave
SDK and the Intel SGX SDK. See that file for the exact package set and the note
about the external Intel/Microsoft apt repositories.

---

## 8. Software environment used for this artifact

- Base image: `ubuntu:20.04`.
- CRIU **3.16.1** (built from source; provides `compel`/`libcompel`).
- `cJSON` (`libcjson-dev`), OpenSSL 1.1 runtime (`libssl1.1`).
- GCC 9 (Ubuntu 20.04 default).
- Open Enclave simulation mode (no SGX driver / `aesmd` needed).

---

## 9. Troubleshooting

- **`could not disable ASLR`** — run the container with `--privileged` (the
  scripts do). ASLR must be `0`; the config addresses are absolute.
- **`libcjson.so.1: not found`** — you are running the monitor outside the
  image; install `libcjson1` or use `hares:latest`.
- **Server never accepts / client cannot connect** — a stale monitor may hold
  the port; `pkill -f hares_monitor` and retry, or change `SERVER_LISTEN_PORT`.
- **Breakpoints never hit** — ASLR is on, or the application binary was rebuilt
  as PIE; rebuild non-PIE and regenerate `config.json` addresses with
  `objdump -d`.
