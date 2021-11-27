CFLAGS = -Wall

LIB_SRC=$(wildcard lib/*.c)

cose-verify: cose-verify.c
	gcc $(CFLAGS) $(LIB_SRC) cose-verify.c -o cose-verify `pkg-config --cflags --libs wolfssl tinycbor`