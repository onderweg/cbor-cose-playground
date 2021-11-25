CFLAGS = -Wall

cose-verify: cose-verify.c
	gcc $(CFLAGS) cose-verify.c -o cose-verify `pkg-config --cflags --libs wolfssl tinycbor`