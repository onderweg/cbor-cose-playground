# My CBOR COSE playground

Playground for working with the CBOR Object Signing and Encryption (COSE) protocol in C.

Goal is to learn more about handling CBOR and COSE with lightweight libraries, that can
run on IoT devices.

## Acknowledgement

This code is in large part based on parts of [HappyEmu/rs_http](https://github.com/HappyEmu/rs_http).
I modified and extended the code, for example HMAC signature handling was added.

## Dependencies

The following libraries are used:

- [tinycbor](https://github.com/intel/tinycbor) - "TinyCBOR is Intel's industrial strength C/C++ implementation of CBOR"
- [wolfssl](https://www.wolfssl.com/) - "lightweight, portable, C-language-based SSL/TLS library targeted at IoT, embedded, and RTOS environments".

## Disclaimer

This repo is just a playground, that might be handy for others to look into as reference or example material.
Don't let this code come anywhere near production.