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
	#oeedger8r ../log_callback.edl --untrusted \
	#	--search-path $(INCDIR) \
	#	--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -g -c $(CFLAGS) log_callback_u.c
	$(CC) -o log_callbackhost log_callback_u.o host.o $(LDFLAGS)

clean:
	rm -f log_callbackhost host.o log_callback_u.o log_callback_u.c log_callback_u.h log_callback_args.h
