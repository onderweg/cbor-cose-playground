/*
 * Encoding demo/tests for COSE messages
 */

#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include "lib/cose.h"
#include "lib/utils.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>

void encode_sign1() {
    // Set values that make the ECC private key.
    cose_ecc_key private_key = {
        .x = "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09ef"
             "f",
        .y = "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc1"
             "17e",
        .d = "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b"
             "4d3", // private key
        .curve_id = ECC_SECP256R1,
    };

    // Define the payload. We use a simple string here.
    char *payload_str = "Hi there";
    bytes payload = {(uint8_t *)payload_str, strlen(payload_str)};

    // Encode protected header
    // COSE headers contain a protected and an un-protected data section. 
    // The cryptographic algorithm used for the signature is specified inside 
    // the protected area.    
    cose_header protected_header;
    cose_header_init(&protected_header);
    cose_header_push(&protected_header,
        cose_label_alg,
        (cose_header_value){.as_int = COSE_ALG_ES256});
    cose_header_push(&protected_header,
        cose_label_KID,
        (cose_header_value){.as_bstr = {(uint8_t *)"11", 2}});

    uint8_t protected_buf[512];
    size_t protected_len;
    cose_encode_header_bytes(&protected_header,
        protected_buf,
        sizeof(protected_buf),
        &protected_len);
    bytes protected = {protected_buf, protected_len};

    // Setup message structure
    cose_sign1_mac_msg msg = {
        .payload = payload,
        .protected_header = protected,
        .unprotected_header = {0},
    };

    bytes external_aad = {NULL, 0};

    // Prepare output data structures
    byte out_buf[512];
    size_t out_size = sizeof(out_buf);
    size_t out_len;

    // Encode and sign the message
    cose_result res = cose_encode_sign1(&msg,
        COSE_ALG_ES256,
        &external_aad,
        &private_key,
        out_buf,
        out_size,
        &out_len);
    if (res != cose_ok) {
        printf("cose encode failed: %d", res);
        exit(EXIT_FAILURE);
    }

    // Print result as a hex string
    printf("sign1 message with EC signature:\n");
    phex(out_buf, out_len);
}

void encode_mac0() {
    byte secret_buf[] = {0xAB, 0xAC, 0xAD};
    size_t secret_size = sizeof(secret_buf);
    bytes secret = {secret_buf, secret_size};

    // Set payload. Will be encoded as byte string (bstr). From COSE specs:
    // "payload is wrapped in a bstr to ensure that it is transported without
    // changes."
    uint8_t payload_buf[] = {
        'h',
        'e',
        'l',
        'l',
        'o',
    }; // acutal payload. Can be anything. In this case ascii string
    size_t payload_len = sizeof(payload_buf);
    bytes payload = {payload_buf, payload_len};

    cose_sign1_mac_msg msg;
    cose_init_mac0(&payload, &msg);

    bytes external_aad = {NULL, 0};

    byte out_buf[512];
    size_t out_size = sizeof(out_buf);
    size_t result_len;

    // Encode the message structure into CBOR.
    cose_encode_mac0(&msg, &external_aad, &secret, out_buf, out_size, &result_len);

    // Print result
    printf("mac0 message with HMAC signature:\n");
    phex(out_buf, result_len);
}

int main(int argc, char *argv[]) {
    encode_mac0();
    encode_sign1();
}