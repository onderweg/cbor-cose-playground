CFLAGS = -Wall

LIB_SRC=$(wildcard lib/*.c)

all: cose-verify cose-encode
.PHONY: all

cose-verify: cose-verify.c
	gcc $(CFLAGS) $(LIB_SRC) cose-verify.c -o cose-verify `pkg-config --cflags --libs wolfssl tinycbor`

cose-encode: cose-encode.c
	gcc $(CFLAGS) $(LIB_SRC) cose-encode.c -o cose-encode `pkg-config --cflags --libs wolfssl tinycbor`	