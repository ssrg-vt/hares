# Hares

**Hares: A Framework for Transparent and Cross-Architecture Enclave Offloading**
*(Middleware 2026)*

Hares is a framework that gives devices **without** a hardware Trusted Execution
Environment (TEE) — including low-end embedded and other-ISA devices — transparent
access to a **remote** hardware enclave (Intel SGX) hosted on an edge/cloud
server. Unmodified applications built with the Intel SGX SDK or the Open Enclave
SDK can run with their enclave part executing securely on a remote SGX node, with
no changes to their source code.

At its core is a userspace **monitor** (`hares_monitor`) that runs on each node
and:

- intercepts enclave transitions (`ecall`/`ocall`) using `ptrace` breakpoints;
- maintains a userspace **distributed shared memory** between the nodes with
  Linux `userfaultfd` and a lightweight MSI coherence protocol;
- injects a small **compel/CRIU parasite** into the traced application to steal
  its page-fault descriptor and align memory regions across nodes.

Hares supports two modes:

- **Binary-compatible mode** — run unmodified Intel SGX SDK binaries on a non-SGX
  x86 node, offloading the enclave to an SGX x86 node.
- **RPC mode** — cross-architecture offloading (e.g. ARM64 → x86 SGX) using an
  extended Open Enclave SDK and an extended `oeedger8r` that marshals ecall
  arguments through a deep-copy buffer with pointer-to-offset conversion.

## Repository layout

| Path | Contents |
|------|----------|
| `src/`, `inc/` | the Hares monitor (`hares_monitor`) |
| `parasite_src/` | the compel parasite injected into the application |
| `Makefile` | builds the monitor (needs CRIU/`compel` + `libcjson`) |
| `oeedger8r-cpp/` | extended Open Enclave `edger8r` (RPC-mode stub generation) |
| `oe-sdk-aarch64/` | prebuilt Open Enclave SDK for ARM64 (RPC mode) |
| `kernel/` | optional custom Linux 5.15 kernel used on the SGX node |
| `tests/` | SGX / Open Enclave applications used in the evaluation |
| **`artifact/`** | **Artifact-evaluation package: Docker build + scripts + guide** |

## Building the monitor

```bash
sudo apt-get install -y build-essential libcjson-dev criu   # + CRIU/compel
make COMPEL=/path/to/criu/compel/compel-host                 # or: make (uses `compel` from $PATH)
# -> bin/hares_monitor
```

The monitor depends on CRIU's `compel` (the paper used CRIU **3.16.1**) and
`libcjson`. The `COMPEL` make variable points to the `compel-host` tool and
defaults to `compel` on your `$PATH`.

## Reproducing the paper / Artifact Evaluation

See **[`artifact/README.md`](artifact/README.md)** for a self-contained,
Docker-based reproduction that runs an enclave-offloading demo **without any SGX
hardware** (Open Enclave simulation mode), plus instructions for the full
two-node hardware setup.

```bash
bash artifact/scripts/build_image.sh   # build the Docker image
bash artifact/scripts/demo.sh          # run the offload demo (no SGX required)
```

## Paper

Abilesh Sundarasamy, Xiaoguang Wang, Carlos Bilbao, and Binoy Ravindran.
*Hares: A Framework for Transparent and Cross-Architecture Enclave Offloading.*
In 27th International Middleware Conference (Middleware '26).
