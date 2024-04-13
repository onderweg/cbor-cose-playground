CFLAGS = -Wall
LIB_SRC=$(wildcard lib/*.c)
TESTS_SRC=$(wildcard tests/*.c)
PKG_FLAGS = `pkg-config --cflags --libs wolfssl tinycbor`

UNAME := $(shell uname)

all: cose-verify cose-encode test
.PHONY: all

cose-verify: cose-verify.c $(LIB_SRC)
	$(CC) $(CFLAGS) $(LIB_SRC) cose-verify.c -o cose-verify $(PKG_FLAGS)

cose-encode: cose-encode.c $(LIB_SRC)
	$(CC) $(CFLAGS) $(LIB_SRC) cose-encode.c -o cose-encode $(PKG_FLAGS)	

test: tests/tests.c $(LIB_SRC)
	cc -g $(CFLAGS) $(LIB_SRC) $(TESTS_SRC) -o test $(PKG_FLAGS) -Ilib
ifeq ($(UNAME), Darwin)
	codesign -s - -f --entitlements ./tests/entitlement.plist ./test
endif
	