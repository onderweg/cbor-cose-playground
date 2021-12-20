/*
 * Verification test for HMAC-SHA256 (HS256) MAC'ed COSE message
 *
 */
#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include "lib/cose.h"
#include "lib/hmac.h"
#include "lib/ecdsa.h"
#include "lib/utils.h"

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
    cose_decode_not_encrypted(
        &msg_bytes, NULL, to_verify_buf, sizeof(to_verify_buf), &signed_msg);

    // Parse protected header
    cose_header protected_header;
    cose_header_init(&protected_header);
    cose_decode_header_bytes(&signed_msg.protected_header, &protected_header);

    cose_header_value *alg = cose_header_get(&protected_header, cose_label_alg);

    char *y;
    buffer_to_hexstring(&y, signed_msg.signature.buf, signed_msg.signature.len);
    printf("Embeded Signature: %s\n", y);

    printf("CBOR tag: %llu\n", signed_msg.tag);
    printf("Signature type in protected header: %i\n", alg->as_int);
    if (alg->as_int == COSE_ALG_HMAC_256) {
        int verified =
            hmac_verify(&signed_msg.to_verify, &signed_msg.signature, &key);
        printf("Verified: %s\n", verified == 1 ? "YES" : "NO");
    }
}

void verify_sign1() {
    // Import key
    ecc_key RS_ID;
    cose_ecc_key RS_ID_ = {
        .x = "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
        .y = "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e",
        .d =
            NULL, // "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
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
    cose_decode_not_encrypted(
        &msg_bytes, NULL, to_verify_buf, sizeof(to_verify_buf), &signed_msg);

    // Decode protected header
    cose_header decoded_protected_header;
    cose_header_init(&decoded_protected_header);
    cose_decode_header_bytes(
        &signed_msg.protected_header, &decoded_protected_header);

    cose_header_value *alg_protected =
        cose_header_get(&decoded_protected_header, cose_label_alg);
    cose_header_value *alg_unprotected =
        cose_header_get(&signed_msg.unprotected_header, cose_label_alg);

    printf("CBOR tag: %llu\n", signed_msg.tag);
    if (alg_protected != NULL) {
        printf(
            "Signature type in protected header: %i\n", alg_protected->as_int);
    }
    if (alg_unprotected != NULL) {
        printf("Signature type in unprotected header: %i\n",
            alg_unprotected->as_int);
    }

    char *to_be_signed_hex;
    buffer_to_hexstring(
        &to_be_signed_hex, signed_msg.to_verify.buf, signed_msg.to_verify.len);
    printf("To Be Signed hex: %s\n", to_be_signed_hex);

    char *signature_hex;
    buffer_to_hexstring(
        &signature_hex, signed_msg.signature.buf, signed_msg.signature.len);
    printf("Signature in message: %s\n", signature_hex);

    char *sig_hex;
    buffer_to_hexstring(
        &sig_hex, signed_msg.signature.buf, signed_msg.signature.len);

    if ((alg_protected != NULL && alg_protected->as_int == COSE_ALG_ES256) ||
        (alg_unprotected != NULL &&
            alg_unprotected->as_int == COSE_ALG_ES256)) {
        int verified = verify_rs_es256(&signed_msg.to_verify, sig_hex, &RS_ID);
        printf("Verified: %s (%i)\n", verified == 1 ? "YES" : "NO", verified);
    }
}

int main(int argc, char *argv[]) {
    verify_mac0();
    printf("-----\n");
    verify_sign1();
}