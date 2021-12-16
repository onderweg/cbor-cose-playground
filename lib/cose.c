#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/integer.h> // mp_toraw

#include "cose.h"
#include "ecdsa.h"
#include "utils.h"

/**
 * Encodes COSE MAC_structure in CBOR.
 * See:
 * https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-how-to-compute-and-verify-a
 */
cose_result cose_encode_mac_structure(const char *context,
    bytes *body_protected, bytes *external_aad, bytes *payload, uint8_t *out,
    size_t out_size, size_t *out_len) {
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

    CborError err = cbor_encoder_close_container(&enc, &ary);
    if (err == CborErrorOutOfMemory) {
        return cose_err_out_of_memory;
    }
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
    return cose_ok;
}

/**
 * Encodes COSE Sig_structure structure in CBOR.
 * See:
 * https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-signing-and-verification-pr
 */
cose_result cose_encode_sig_structure(const char *context,
    bytes *body_protected, bytes *external_aad, bytes *payload, uint8_t *out,
    size_t out_size, size_t *out_len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);
    cbor_encode_text_stringz(&ary, context);
    // Encode protected header
    if (body_protected->len > 0 && body_protected->buf[0] == 0xa0) {
        // Senders SHOULD encode a zero-length map as a zero-
        // length string rather than as a zero-length map (encoded as h'a0')
        cbor_encode_byte_string(&ary, NULL, 0);
    } else {
        cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);
    }

    // Encode external aad
    if (external_aad != NULL) {        
        cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);
    } else {        
        cbor_encode_byte_string(&ary, NULL, 0);
    }

    // Encode payload
    cbor_encode_byte_string(&ary, payload->buf, payload->len);

    CborError err = cbor_encoder_close_container(&enc, &ary);
    if (err == CborErrorOutOfMemory) {
        return cose_err_out_of_memory;
    }
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
    return cose_ok;
}

void cose_init_header(cose_header *out) {
    out->alg = 0;
    out->content_type = 0;
}

/**
 * Encodes a protected header to a CBOR 'bstr' from a struct
 */
void cose_encode_header_bytes(
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
    if (hdr == NULL || hdr->alg ==0) {
        cbor_encoder_create_map(enc, &map, 0);
        cbor_encoder_close_container(enc, &map);    
        return;

    }    
    cbor_encoder_create_map(enc, &map, 1); // length not yet determined    
    if (hdr != NULL) {
           
            cbor_encode_int(&map, 1);
            cbor_encode_int(&map, hdr->alg);
     
    }
    cbor_encoder_close_container(enc, &map);    
}

/**
 * Decodes COSE protected header (CBOR 'bstr' type) to a struct
 */
cose_result cose_decode_protected_header(bytes *protected, cose_header *out) {
    cose_init_header(out);
    CborParser parser;
    CborValue cborValue;
    cbor_parser_init(protected->buf, protected->len, 0, &parser, &cborValue);
    return cose_decode_header(&cborValue, out);
}

/**
 * Decodes a COSE header (CBOR map) into a struct.
 * (Both protected and unprotected maps use the same set of label/value pairs. )
 */
cose_result cose_decode_header(CborValue *cborValue, cose_header *out) {
    if (!cbor_value_is_map(cborValue)) {
        return cose_err_unexpected;
    }
    CborValue map;
    cbor_value_enter_container(cborValue, &map);
    int key;
    while (!cbor_value_at_end(&map)) {
        // We expect integer keys in the protected header
        if (!cbor_value_is_integer(&map)) {
            return cose_err_unexpected;
        }
        // Get key
        cbor_value_get_int_checked(&map, &key);
        cbor_value_advance_fixed(&map);
        if (key == cose_label_alg) { // alg
            cbor_value_get_int_checked(&map, &out->alg);
            cbor_value_advance_fixed(&map);
        } else if (key == cose_label_content_type) { // content type
            cbor_value_get_uint64(&map, &out->content_type);
            cbor_value_advance_fixed(&map);
        } else {
            cbor_value_advance(&map);
        }
    }
    cbor_value_leave_container(cborValue, &map);
    return cose_ok;
}

/**
 * Compare calculated HMAC 256 signature to provided signature.
 *
 * Returns 1 when signature is valid, 0 if invalid
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
    return (ret == 0);
}

/**
 * Decode sign1/mac0 tagged message and calculate bytes to be verified
 *
 * Type type is derived from the optional tag in the message. If the message is
 * untagged, type provided in the out structure is being used.
 */
cose_result cose_decode_sign1_mac0(bytes *sign1, bytes *external_aad,
    uint8_t *calculated_sig_buf, size_t calculated_sig_size,
    cose_sign1_mac_msg *out) {

    CborParser parser;
    CborValue val;
    cbor_parser_init(sign1->buf, sign1->len, 0, &parser, &val);

    // Validate
    CborError err = cbor_value_validate(&val, 0);
    if (err != CborNoError) {
        return cose_err_cbor_invalid;
    }

    CborTag tag = out->tag;
    if (cbor_value_is_tag(&val)) { // tag is optional, if present, get tag
        cbor_value_get_tag(&val, &tag);
        cbor_value_advance(&val);
    }

    CborValue e;
    cbor_value_enter_container(&val, &e);

    // Get protected header (COSE protected header is wrapped in a 'bstr')
    bytes protected;
    cbor_value_dup_byte_string(&e, &protected.buf, &protected.len, &e);

    // Get unprotected header (CBOR 'map' type), if not empty
    cose_header unprotected;
    cose_init_header(&unprotected);
    if (cbor_value_is_map(&e)) {
        cose_decode_header(&e, &unprotected);
    } else {
        cbor_value_advance(&e); // skip empty unprotected header
    }

    // Get payload (COSE payload is wrapped in a 'bstr')
    bytes payload;
    cbor_value_dup_byte_string(&e, &payload.buf, &payload.len, &e);

    // Get signature (sign1) or tag (mac0)
    bytes signature;
    cbor_value_dup_byte_string(&e, &signature.buf, &signature.len, &e);

    // Calculate bytes to verify.
    size_t to_verify_len = 0;
    if (tag == CborCOSE_Sign1Tag) {
        err = cose_encode_sig_structure("Signature1",
            &protected,
            external_aad,
            &payload,
            calculated_sig_buf,
            calculated_sig_size,
            &to_verify_len);
    } else if (tag == CborCOSE_Mac0Tag) {
        err = cose_encode_mac_structure("MAC0",
            &protected,
            external_aad,
            &payload,
            calculated_sig_buf,
            calculated_sig_size,
            &to_verify_len);
    } else {
        return cose_err_unsupported;
    }
    if (err != cose_ok)
        return err;
    bytes to_verify = (bytes){calculated_sig_buf, to_verify_len};

    out->tag = tag;
    out->payload = payload;
    out->protected_header = protected;
    out->unprotected_header = unprotected;
    out->signature = signature;
    out->to_verify = to_verify;
    return cose_ok;
}

/**
 * Encode a COSE_Mac0 message
 */
cose_result cose_encode_mac0(cose_sign1_mac_msg *msg, bytes *external_aad,
    bytes *secret, uint8_t *out, size_t out_size, size_t *out_len) {
    uint8_t sign_buf[512];
    size_t sign_len = sizeof(sign_buf);

    // Create MAC structure and encode it
    cose_encode_mac_structure("MAC0",
        &msg->protected_header,
        external_aad,
        &msg->payload,
        sign_buf,
        sizeof(sign_buf),
        &sign_len);

    // Apply MAC
    Hmac hmac;
    byte hmacDigest[SHA256_DIGEST_SIZE];
    wc_HmacSetKey(&hmac, WC_SHA256, secret->buf, secret->len);
    wc_HmacUpdate(&hmac, sign_buf, sign_len);
    wc_HmacFinal(&hmac, hmacDigest);

    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, CborCOSE_Mac0Tag);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_byte_string(
        &ary, msg->protected_header.buf, msg->protected_header.len);
    cose_encode_header(&ary, &msg->unprotected_header);

    cbor_encode_byte_string(&ary, msg->payload.buf, msg->payload.len);
    cbor_encode_byte_string(&ary, hmacDigest, SHA256_DIGEST_SIZE);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
    return cose_ok;
}

cose_result cose_encode_sign1(cose_sign1_mac_msg *msg, bytes *external_aad,
    ecc_key *private_key, uint8_t *out, size_t out_size, size_t *out_len) {
    uint8_t to_sign_buf[512];
    size_t to_sign_len = sizeof(to_sign_buf);

    // Create MAC structure and encode it
    cose_encode_sig_structure("Signature1",
        &msg->protected_header,
        external_aad,
        &msg->payload,        
        to_sign_buf,
        sizeof(to_sign_buf),
        &to_sign_len);

    // Calculate signature
    mp_int r; // destination for r component of signature.
    mp_int s; // destination for s component of signature.
    bytes to_sign = {to_sign_buf, to_sign_len};
    sign_es256(&to_sign, private_key, &r, &s);

    // Convert signature R, S components to binary string
    int key_size = wc_ecc_size(private_key);
    unsigned char buf_r[key_size];
    unsigned char buf_s[key_size];
    mp_to_unsigned_bin(&r, buf_r);
    mp_to_unsigned_bin(&s, buf_s);

    // Concat R, S binary strings into one binary string
    byte signature[key_size * 2];
    memcpy(signature, buf_r, key_size);
    memcpy(signature + key_size, buf_s, key_size);

    // Cleanup
    mp_clear(&r);
    mp_clear(&s);

    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, CborCOSE_Sign1Tag);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_byte_string(
        &ary, msg->protected_header.buf, msg->protected_header.len);
    cose_encode_header(&ary, &msg->unprotected_header);

    cbor_encode_byte_string(&ary, msg->payload.buf, msg->payload.len);

    cbor_encode_byte_string(&ary, signature, key_size * 2);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
    return cose_ok;
}