#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "cose.h"
#include "utils.h"

/**
 * Encodes COSE MAC_structure in CBOR.
 * See:
 * https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-how-to-compute-and-verify-a
 */
void cose_encode_mac_structure(const char *context, bytes *body_protected,
    bytes *external_aad, bytes *payload, uint8_t *out, size_t out_size,
    size_t *out_len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_text_stringz(&ary, context);
    cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);
    if (external_aad != NULL) {
        cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);
    } else {
        cbor_encode_byte_string(&ary, NULL, 0);
    }
    cbor_encode_byte_string(&ary, payload->buf, payload->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

/**
 * Encodes COSE Sig_structure structure in CBOR.
 * See:
 * https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-signing-and-verification-pr
 */
void cose_encode_sig_structure(const char *context, bytes *body_protected,
    bytes *external_aad, bytes *payload, uint8_t *out, size_t out_size,
    size_t *out_len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_text_stringz(&ary, context);
    cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);
    if (external_aad != NULL) {
        cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);
    } else {
        cbor_encode_byte_string(&ary, NULL, 0);
    }
    cbor_encode_byte_string(&ary, payload->buf, payload->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

/**
 * Encodes a protected header to a CBOR 'bstr' from a struct
 */
void cose_encode_protected_header(
    cose_header *hdr, uint8_t *out, size_t out_size, size_t *out_len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cose_encode_header(&enc, hdr);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

/**
 * Encodes a protected header from a struct
 */
void cose_encode_header(CborEncoder *enc, cose_header *hdr) {
    CborEncoder map;
    cbor_encoder_create_map(enc, &map, 1);
    cbor_encode_int(&map, 1);
    cbor_encode_int(&map, hdr->alg);
    cbor_encoder_close_container(enc, &map);
}

/**
 * Decodes cose protected header (CBOR 'bstr' type) to a struct
 */
void cose_decode_protected_header(bytes *protected, cose_header *out) {
    CborParser parser;
    CborValue cborValue;
    cbor_parser_init(protected->buf, protected->len, 0, &parser, &cborValue);
    cose_decode_header(&cborValue, out);
}

/**
 * Decodes a COSE header (CBOR map) into a struct.
 * (Both protected and unprotected maps use the same set of label/value pairs. )
 */
void cose_decode_header(CborValue *cborValue, cose_header *out) {
    if (!cbor_value_is_container(cborValue)) {
        return; // @TODO: better error handling
    }
    CborValue map;
    cbor_value_enter_container(cborValue, &map);
    int key;
    while (!cbor_value_at_end(&map)) {
        // We expect integer keys in the protected header
        if (!cbor_value_is_integer(&map)) {
            return;
        }
        // Get key
        cbor_value_get_int_checked(&map, &key);
        cbor_value_advance_fixed(&map);
        if (key == 1) // alg
        {
            cbor_value_get_int_checked(&map, &out->alg);
            cbor_value_advance_fixed(&map);
        } else if (key == 3) { // content type
            cbor_value_get_uint64(&map, &out->content_type);
            cbor_value_advance_fixed(&map);
        } else {
            cbor_value_advance(&map);
        }
    }
    cbor_value_leave_container(cborValue, &map);
}

/**
 * Compare calculated HMAC 256 signature with provided signature
 */
int verify_hmac(bytes *to_verify, bytes *signature, bytes *secret) {
    Hmac hmac;
    byte hmacDigest[SHA256_DIGEST_SIZE];

    wc_HmacSetKey(&hmac, WC_SHA256, secret->buf, secret->len);

    wc_HmacUpdate(&hmac, to_verify->buf, to_verify->len);
    wc_HmacFinal(&hmac, hmacDigest);

    char *x;
    buffer_to_hexstring(&x, hmacDigest, SHA256_DIGEST_SIZE);
    printf("Calculated Signature: %s\n", x);

    char *y;
    buffer_to_hexstring(&y, signature->buf, signature->len);
    printf("Embeded Signature: %s\n", y);

    int ret = memcmp(hmacDigest, signature->buf, SHA256_DIGEST_SIZE);
    return ret;
}

/**
 * Verify ES256 (SHA256 with ECDSA) signature.
 */
int verify_es256(bytes *to_verify, bytes *signature, ecc_key *key) {
    // Compute digest
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, to_verify->buf, (word32)to_verify->len);
    wc_Sha256Final(&sha, digest);

    int ret, verified = 0;
    ret = wc_ecc_verify_hash(signature->buf,
        (word32)signature->len,
        digest,
        sizeof(digest),
        &verified,
        key);

    return verified;
}

/**
 * Decode sign1/mac0 message and calculate bytes to be verified
 */
void cose_decode_sign1_mac0(bytes *sign1, bytes *external_aad,
    uint8_t *calculated_sig_buf, size_t calculated_sig_size,
    cose_sign1_mac_msg *out) {
    // Parse
    CborParser parser;
    CborValue val;
    cbor_parser_init(sign1->buf, sign1->len, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    // Get protected header (CBOR 'bstr' type)
    bytes protected;
    cbor_value_dup_byte_string(&e, &protected.buf, &protected.len, &e);

    // Get unprotected header (CBOR 'map' type), if not empty
    cose_header unprotected = {.alg = 0};
    if (cbor_value_is_map(&e)) {
        cose_decode_header(&e, &unprotected);
    } else {
        cbor_value_advance(&e); // skip empty unprotected header
    }

    // Get payload
    bytes payload;
    cbor_value_dup_byte_string(&e, &payload.buf, &payload.len, &e);

    // Get signature (sign1) or tag (mac0)
    bytes signature;
    cbor_value_dup_byte_string(&e, &signature.buf, &signature.len, &e);

    // Calculate bytes to verify.
    size_t to_verify_len = 0;
    if (tag == CborCOSE_Sign1Tag) {
        cose_encode_sig_structure("Signature1",
            &protected,
            external_aad,
            &payload,
            calculated_sig_buf,
            calculated_sig_size,
            &to_verify_len);
    } else if (tag == CborCOSE_Mac0Tag) {
        cose_encode_mac_structure("MAC0",
            &protected,
            external_aad,
            &payload,
            calculated_sig_buf,
            calculated_sig_size,
            &to_verify_len);
    }
    bytes to_verify = (bytes){calculated_sig_buf, to_verify_len};

    out->tag = tag;
    out->payload = payload;
    out->protected_header = protected;
    out->unprotected_header = unprotected;
    out->signature = signature;
    out->to_verify = to_verify;
}

/**
 * Encode a mac0 message
 */
void cose_encode_mac0(cose_sign1_mac_msg *sign1, byte *secret,
    size_t secret_size, uint8_t *out, size_t out_size, size_t *out_len) {
    uint8_t sign_buf[512];
    size_t sign_len = sizeof(sign_buf);
    bytes external_aad = {NULL, 0};

    // Create MAC structure and encode it
    cose_encode_mac_structure("MAC0",
        &sign1->protected_header,
        &external_aad,
        &sign1->payload,
        sign_buf,
        sizeof(sign_buf),
        &sign_len);

    // Apply MAC
    Hmac hmac;
    byte hmacDigest[SHA256_DIGEST_SIZE];
    wc_HmacSetKey(&hmac, WC_SHA256, secret, secret_size);
    wc_HmacUpdate(&hmac, sign_buf, sign_len);
    wc_HmacFinal(&hmac, hmacDigest);

    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, CborCOSE_Mac0Tag);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_byte_string(
        &ary, sign1->protected_header.buf, sign1->protected_header.len);
    cose_encode_header(&ary, &sign1->unprotected_header);

    cbor_encode_byte_string(&ary, sign1->payload.buf, sign1->payload.len);
    cbor_encode_byte_string(&ary, hmacDigest, SHA256_DIGEST_SIZE);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}