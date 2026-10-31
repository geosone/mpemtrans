CC ?= cc
CRYPTLIB_INCLUDE ?= /usr/include
CFLAGS ?= -O2 -Wall -Wextra -Wno-deprecated-declarations -fstack-protector-strong
CPPFLAGS += -I$(CRYPTLIB_INCLUDE)
LDLIBS ?= -lcrypto -ldl -pthread

.PHONY: all clean
all: build/mpemtrans
build/mpemtrans: mpemtrans.c
	mkdir -p build
	$(CC) -std=c11 $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@
clean:
	rm -rf build
