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
	#../oeedger8r ../helloworld.edl --untrusted --popsgx_client \
	#	--search-path $(INCDIR) \
	#	--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -g -c $(CFLAGS) helloworld_u.c
	$(CC) -o helloworld_host helloworld_u.o host.o $(LDFLAGS)

clean:
	rm -f helloworld_host host.o helloworld_u.o helloworld_u.c helloworld_u.h helloworld_args.h
