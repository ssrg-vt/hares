# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)
CFLAGS += -I/home/oe-sdk-aarch64/include/openenclave/3rdparty/optee/liboeutee/
LDFLAGS+= -lteec -L/home/oe-sdk-aarch64/lib/openenclave/optee/libteec

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	#oeedger8r ../debugmalloc.edl --untrusted \
	#	--search-path $(INCDIR) \
	#	--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -g -c $(CFLAGS) debugmalloc_u.c
	$(CC) -o debugmallochost debugmalloc_u.o host.o $(LDFLAGS)

clean:
	rm -f debugmallochost host.o debugmalloc_u.o debugmalloc_u.c debugmalloc_u.h debugmalloc_args.h
