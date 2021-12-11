/*
 * Verification test for HMAC-SHA256 (HS256) MAC'ed COSE message
 *
 */

#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include "lib/cose.h"
#include "lib/utils.h"

typedef struct rs_key {
    char *x;
    char *y;
    char *d;
    ecc_curve_id curve_id;
} rs_key;

void verify_mac0() {
    cose_sign1_mac_msg signed_msg;
    byte *msg_buf, *key_buf;

    // Example HMAC-SHA256 signed COSE message
    // Source: // Source:
    // https://github.com/cose-wg/Examples/blob/3221310e2cf50ad13213daa7ca278209a8bc85fd/mac0-tests/HMac-01.json
    char *msg_hex =
        "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D347"
        "1F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58";

    // Convert message hex string to bytes
    size_t msg_len = hexstring_to_buffer(&msg_buf, msg_hex, strlen(msg_hex));

    char *key_hex =
        "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188";
    size_t key_len = hexstring_to_buffer(&key_buf, key_hex, strlen(key_hex));
    bytes key = {key_buf, key_len};

    // Decode CBOR message
    bytes msg_bytes = {msg_buf, msg_len};
    uint8_t to_verify_buf[1024];
    cose_decode_sign1_mac0(
        &msg_bytes, NULL, to_verify_buf, sizeof(to_verify_buf), &signed_msg);

    // Parse protected header
    cose_header protected_header;
    cose_init_header(&protected_header);
    cose_decode_protected_header(
        &signed_msg.protected_header, &protected_header);

    printf("CBOR tag: %llu\n", signed_msg.tag);
    printf("Signature type in protected header: %i\n", protected_header.alg);
    if (protected_header.alg == COSE_ALG_HMAC_256) {
        int verified =
            verify_hmac(&signed_msg.to_verify, &signed_msg.signature, &key);
        printf("Verified: %s\n", verified == 0 ? "YES" : "NO");
    }
}

void verify_sign1() {
    // Import key
    ecc_key RS_ID;
    rs_key RS_ID_ = {
        .x = "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
        .y = "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e",
        .d = NULL, // "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
                   // // private key
        .curve_id = ECC_SECP256R1};
    wc_ecc_import_raw_ex(&RS_ID, RS_ID_.x, RS_ID_.y, RS_ID_.d, RS_ID_.curve_id);

    // Key check
    int check = wc_ecc_check_key(&RS_ID);
    printf("Key check: %s\n", check == MP_OKAY ? "OKAY" : "FAIL");
    if (check != MP_OKAY) {
        return;
    }

    cose_sign1_mac_msg signed_msg;
    byte *msg_buf;

    // Example ES256 signed COSE message
    // Source:
    // https://github.com/cose-wg/Examples/blob/3221310e2cf50ad13213daa7ca278209a8bc85fd/sign1-tests/sign-pass-01.json
    char *msg_hex =
        "D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087"
        "DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E5612"
        "7FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F";

    // Convert message hex to bytes
    size_t msg_len = hexstring_to_buffer(&msg_buf, msg_hex, strlen(msg_hex));

    // Decode CBOR message
    bytes msg_bytes = {msg_buf, msg_len};
    uint8_t to_verify_buf[1024];
    cose_decode_sign1_mac0(
        &msg_bytes, NULL, to_verify_buf, sizeof(to_verify_buf), &signed_msg);

    printf("CBOR tag: %llu\n", signed_msg.tag);
    printf("Signature type in unprotected header: %i\n",
        signed_msg.unprotected_header.alg);

    if (signed_msg.unprotected_header.alg == COSE_ALG_ES256) {
        int verified =
            verify_es256(&signed_msg.to_verify, &signed_msg.signature, &RS_ID);
        printf("Verified: %s\n", verified == 0 ? "YES" : "NO");
    }
}

int main(int argc, char *argv[]) {
    verify_mac0();
    printf("-----\n");
    verify_sign1();
}