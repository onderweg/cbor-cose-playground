# My CBOR COSE playground

Incomplete implementation of the [CBOR](https://cbor.io/) Object Signing and Encryption ([COSE](https://datatracker.ietf.org/doc/html/rfc8152)) protocol in C.

Goal is to learn more about handling CBOR and COSE with lightweight libraries, that can
run on IoT devices.

## Acknowledgement

[HappyEmu/rs_http](https://github.com/HappyEmu/rs_http) was used as a basis/inspiration for this code.

## Dependencies

The following libraries are needed to use the code:

- [tinycbor](https://github.com/intel/tinycbor) - "TinyCBOR is Intel's industrial strength C/C++ implementation of CBOR"
- [wolfssl](https://www.wolfssl.com/) - "lightweight, portable, C-language-based SSL/TLS library targeted at IoT, embedded, and RTOS environments".
    - On Mac: `brew install wolfssl`
    - *note*: wolfssl should be compiled with `WOLFSSL_PUBLIC_MP`, `WOLFSSL_PUB_PEM_TO_DER`, `WOLFSSL_DER_TO_PEM` (for `wc_PemPubKeyToDer()`) defined: `./configure C_EXTRA_FLAGS="-DWOLFSSL_PUBLIC_MP -DWOLFSSL_PUB_PEM_TO_DER"`

Install Tinycbor:

    $ git clone https://github.com/intel/tinycbor
    $ make
    $ make install

Install WolfSSL:

    $ git clone https://github.com/wolfssl/wolfssl.git
    $ cd wolfssl
    $ ./autogen.sh
    $ ./configure
    $ make
    $ sudo make install    

## Notes

- Currently only works with Sign1 and Mac0 COSE messages.
- Design goals:
    - Keep dynamic memory allocation (`malloc`, etc) to a minimum. Currently allocation is only used in:
        - Results from `cbor_value_dup_byte_string`
        - Member `pairs` of `cose_header` struct (implemented as dynamic array)

### Creating a new ECDSA ECC key pair

Signing COSE messages is done with Elliptic Curve Digital Signature Algorithm (ECDSA) . You need a private/public key pair
to sign and verify messages.

Create ECC key pair with openssl:

```bash
# generate a private key for a curve. primve256v1, also known as P-256 and secp256r1
$ openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

# generate corresponding public key
$ openssl ec -in private-key.pem -pubout -out public-key.pem        
```

### Todo

[] Free memory allocated by Tinycbor decoder

## Disclaimer

This repo is just a playground. It might come in handy for others to look into as reference or as example material (I did not find a lot of examples of COSE handling in C).
Code in this repo is in no way stable. Don't let this code come anywhere near production.