# Hares artifact-evaluation image.
#
# Ubuntu 20.04 (the environment reported in the paper) with:
#   * a full C toolchain,
#   * CRIU 3.16.1 built from source (provides the `compel` parasite-injection
#     tool + libcompel used by the Hares monitor),
#   * the Hares monitor (popSGX_Monitor) built from src/,
#   * the Open Enclave *runtime* libraries needed to run the prebuilt
#     simulation-mode sample enclaves (libssl1.1, libcjson1).
#
# No SGX hardware is required: the sample enclaves run in Open Enclave
# simulation mode.  See artifact/README.md.
#
# Build (from the repository root):
#   docker build -f artifact/docker/Dockerfile -t hares:latest .
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

# ---------------------------------------------------------------------------
# Toolchain + monitor deps (libcjson) + OE runtime libs (libssl1.1)
# + CRIU 3.16.1 build dependencies.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config git wget ca-certificates make gdb \
        libcjson-dev libcjson1 libssl1.1 \
        libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler \
        python3 python3-protobuf \
        libnl-3-dev libnl-route-3-dev libnet1-dev libcap-dev libbsd-dev \
        libaio-dev libgnutls28-dev uuid-dev iproute2 \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# CRIU 3.16.1 - only the `compel` component is needed by the monitor.
# ---------------------------------------------------------------------------
ARG CRIU_VERSION=3.16.1
RUN cd /opt \
 && wget -q https://github.com/checkpoint-restore/criu/archive/refs/tags/v${CRIU_VERSION}.tar.gz \
 && tar xf v${CRIU_VERSION}.tar.gz && mv criu-${CRIU_VERSION} criu && rm -f v${CRIU_VERSION}.tar.gz \
 && make -C /opt/criu -j"$(nproc)" \
        compel/compel-host-bin \
        compel/libcompel.a \
        compel/plugins/std.lib.a \
        compel/plugins/fds.lib.a \
 && /opt/criu/compel/compel-host --version
ENV COMPEL=/opt/criu/compel/compel-host

# ---------------------------------------------------------------------------
# Build the Hares monitor from source.  The parasite is regenerated with the
# container's own compel so the blob and libcompel always match.
# ---------------------------------------------------------------------------
WORKDIR /opt/hares
COPY Makefile ./Makefile
COPY src ./src
COPY inc ./inc
COPY parasite_src ./parasite_src
RUN make parasite_clean 2>/dev/null; make COMPEL="$COMPEL" -j"$(nproc)" \
 && install -m0755 bin/popSGX_Monitor /usr/local/bin/popSGX_Monitor

# ---------------------------------------------------------------------------
# Sample apps + orchestration scripts for the simulation-mode demo.
# ---------------------------------------------------------------------------
COPY artifact/apps    /opt/hares/artifact/apps
COPY artifact/scripts /opt/hares/artifact/scripts

WORKDIR /opt/hares
CMD ["/bin/bash"]
