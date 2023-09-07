# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)

# Disable positional independent code
# LDFLAGS+=" -no-pie emerge -v1 foo-package"

INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r -Wno-non-portable-type ../microbench.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) -fno-stack-protector -ggdb host.c -I/usr/include
	$(CC) -g -c $(CFLAGS) -fno-stack-protector -ggdb microbench_u.c -I/usr/include 
	$(CC) -o microbenchhost microbench_u.o host.o $(LDFLAGS) $(CRYPTO_FLAGS)

clean:
	rm -f microbenchhost host.o microbench_u.o microbench_u.c microbench_u.h microbench_args.h
