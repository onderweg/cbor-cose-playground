/*
 * Verification test for HMAC-SHA256 (HS256) MAC'ed COSE message
 *
 */

#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include "lib/cose.h"
#include "lib/utils.h"

#include <wolfssl/wolfcrypt/ecc.h>

void encode_sign1() {
    // Import key
    ecc_key key;
    cose_ecc_key private_key = {
        .x = "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09ef"
             "f",
        .y = "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc1"
             "17e",
        .d = "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b"
             "4d3", // private key
        .curve_id = ECC_SECP256R1};
    wc_ecc_import_raw_ex(&key,
        private_key.x,
        private_key.y,
        private_key.d,
        private_key.curve_id);

    char *payload_str = "Hi there";
    bytes payload = {(uint8_t *)payload_str, strlen(payload_str)};

    // Encode protected header
    uint8_t protected_buf[512];
    size_t protected_len;
    cose_header protected_header = {.alg = COSE_ALG_ES256};
    cose_encode_header_bytes(&protected_header,
        protected_buf,
        sizeof(protected_buf),
        &protected_len);
    bytes protected = {protected_buf, protected_len};

    // Unprotected heaer
    /*
    uint8_t unprotected_buf[512];
    size_t unprotected_len;
    printf("+++\n");
    cose_encode_header_bytes(
        NULL,
        unprotected_buf,
        sizeof(unprotected_buf),
        &unprotected_len);
    printf("----\n");
    bytes unprotected = {unprotected_buf, unprotected_len};
    */
    cose_sign1_mac_msg msg = {
        .payload = payload,
        .protected_header = protected,
        .unprotected_header = {0},
    };

    bytes external_aad = {NULL, 0};

    byte out_buf[512];
    size_t out_size = sizeof(out_buf);
    size_t out_len;

    cose_encode_sign1(&msg, &external_aad, &key, out_buf, out_size, &out_len);

    // Print result
    printf("Sign message:\n");
    phex(out_buf, out_len);
}

int main(int argc, char *argv[]) {
    /*
    byte secret_buf[] = {0xAB, 0xAC, 0xAD};
    size_t secret_size = sizeof(secret_buf);
    bytes secret = {secret_buf, secret_size};

    // Encode payload, encoded as bstr. From COSE specs:
    // "payload is wrapped in a bstr to ensure that it is transported without
    // changes. "
    byte *payload_buf;
    char *payload_hex = "684869207468657265"; // CBOR encoded text "Hi there"
    size_t payload_len =
        hexstring_to_buffer(&payload_buf, payload_hex, strlen(payload_hex));
    bytes payload = {payload_buf, payload_len};

    // Encode protected header

    // uint8_t protected_buf[512];
    // size_t protected_len;
    // cose_header protected_header = {
    //     .alg = COSE_ALG_HMAC_256};
    // cose_encode_protected_header(
    //     &protected_header,
    //     protected_buf,
    //     512,
    //     &protected_len
    // );

    bytes protected = {NULL, 0};

    cose_sign1_mac_msg msg = {
        .payload = payload,
        .protected_header = protected,
        .unprotected_header =
            {
                .alg = COSE_ALG_HMAC_256,
            },
    };

    bytes external_aad = {NULL, 0};

    byte out_buf[512];
    size_t out_size = sizeof(out_buf);
    size_t out_len;

    cose_encode_mac0(&msg, &external_aad, &secret, out_buf, out_size, &out_len);

    // Print result
    printf("mac0 message with HMAC signature:\n");
    phex(out_buf, out_len);
*/
    encode_sign1();
}