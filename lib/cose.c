/* An incomplete Concise Binary Object Representation (CBOR) library.
 *
 * Copyright (c) 2021, G. Stevens <dev at onderweg dot eu>
 *
 * USE AT YOUR OWN RISK. I threw this together as a personal learning
 * experiment.
 */

#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include "cose.h"
#include "ecdsa.h"
#include "hmac.h"
#include "utils.h"

/** Initial capacity for COSE header array */
static int const initial_header_capacity = 5;

/**
 * Allocates memory for the inital capacity of the header parameter array
 */
void cose_header_init(cose_header *hdr) {
    assert(hdr != NULL);
    hdr->pairs = malloc(sizeof(cose_header_pair) * initial_header_capacity);
    hdr->size = 0;
    hdr->capacity = initial_header_capacity;
}

/**
 * Adds a COSE header paramater (label/value pair) to an
 * existing COSE header structure.
 *
 * @note Before this function can be used, the header structure has to be
 * initialised with `cose_header_init`.
 */
void cose_header_push(cose_header *hdr, int label, cose_header_value value) {
    assert(hdr != NULL);
    // Dynamic array: if capacity is not enough, grow array
    if (hdr->size == hdr->capacity) {
        hdr->capacity *= 2;
        hdr->pairs =
            realloc(hdr->pairs, hdr->capacity * sizeof(cose_header_pair));
    }
    hdr->pairs[hdr->size] = (cose_header_pair){label, value};
    hdr->size++;
}

/**
 * Frees the array of header pairs
 */
void cose_header_free(cose_header *hdr) {
    assert(hdr != NULL);
    free(hdr->pairs);
    hdr->size = 0;
}

/**
 * Retrieves first header parameter with provided label from set of header
 * parameters.
 *
 * @note Before this function can be used, the header structure MUST be
 * initialised with `cose_header_init`.
 *
 * @returns Header value for label, or NULL if not found.
 */
cose_header_value *cose_header_get(cose_header *hdr, int label) {
    assert(hdr != NULL);
    for (int i = 0; i < hdr->size; i++) {
        if (hdr->pairs[i].label == label) {
            return &hdr->pairs[i].val;
        }
    }
    return NULL;
}

/**
 * Encodes COSE MAC_structure in CBOR.
 *
 * See:
 * https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-how-to-compute-and-verify-a
 *
 * @returns Result of operation
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
 *
 * See:
 * https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-signing-and-verification-pr
 *
 * @returns Result of operation
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
        // "Senders SHOULD encode a zero-length map as a zero-
        // length string rather than as a zero-length map (encoded as h'a0')""
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

/**
 * Encodes a (protected) header to a CBOR `bstr` from a header struct
 */
void cose_encode_header_bytes(
    cose_header *hdr, uint8_t *out, size_t out_size, size_t *out_len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cose_encode_header(&enc, hdr);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

/**
 * Encodes a (protected) header to a CBOR `bstr` with a `CborEncoder`.
 */
void cose_encode_header(CborEncoder *enc, cose_header *hdr) {
    CborEncoder map;
    if (hdr == NULL) {
        cbor_encoder_create_map(enc, &map, 0);
        cbor_encoder_close_container(enc, &map);
        return;
    }
    cbor_encoder_create_map(enc, &map, hdr->size);
    for (int i = 0; i < hdr->size; i++) { // @todo make generic
        if (hdr->pairs[i].label == cose_label_alg) {
            cbor_encode_int(&map, cose_label_alg);
            cbor_encode_int(&map, hdr->pairs[i].val.as_int);
        } else if (hdr->pairs[i].label == cose_label_KID) {
            bytes str = hdr->pairs[i].val.as_bstr;
            cbor_encode_int(&map, cose_label_KID);
            cbor_encode_byte_string(&map, str.buf, str.len);
        } else {
            cbor_encode_int(&map, hdr->pairs[i].label);
            cbor_encode_undefined(&map);
        }
    }
    cbor_encoder_close_container(enc, &map);
}

/**
 * Decodes COSE header that is a binary string (CBOR 'bstr' type).
 *
 */
cose_result cose_decode_header_bytes(bytes *protected, cose_header *out) {
    CborParser parser;
    CborValue cborValue;
    cbor_parser_init(protected->buf, protected->len, 0, &parser, &cborValue);
    return cose_decode_header(&cborValue, out);
}

/**
 * Decodes a COSE header that is a `CborValue`.
 * (Both protected and unprotected headers use the same set of label/value
 * pairs.)
 */
cose_result cose_decode_header(CborValue *cborValue, cose_header *out) {
    if (!cbor_value_is_map(cborValue)) {
        return cose_err_unexpected;
    }
    CborValue map;
    cbor_value_enter_container(cborValue, &map);
    int key;
    cose_header_value val;
    CborError err;
    while (!cbor_value_at_end(&map)) {
        // We expect integer keys in the protected header
        if (!cbor_value_is_integer(&map)) {
            return cose_err_unexpected;
        }
        // Get key
        cbor_value_get_int_checked(&map, &key);
        cbor_value_advance_fixed(&map);
        if (cbor_value_is_integer(&map)) { // int value
            err = cbor_value_get_int_checked(&map, &val.as_int);
            if (err == CborErrorDataTooLarge) {
                cbor_value_get_int64(&map, &val.as_int64);
            }
            cbor_value_advance_fixed(&map);
            cose_header_push(out, key, val);
        } else if (cbor_value_is_unsigned_integer(&map)) { // uint value
            cbor_value_get_uint64(&map, &val.as_uint64);
            cbor_value_advance_fixed(&map);
            cose_header_push(out, key, val);
        } else if (cbor_value_is_byte_string(&map)) { // bstr value
            cbor_value_dup_byte_string(
                &map, &val.as_bstr.buf, &val.as_bstr.len, &map);
            cose_header_push(out, key, val);
        } else {
            cbor_value_advance(&map);
        }
    }
    cbor_value_leave_container(cborValue, &map);
    return cose_ok;
}

/**
 * Decode sign1/mac0 tagged message and calculate bytes to be verified
 *
 * Type is derived from the optional tag in the message. If the message
 * is untagged, type provided in the out structure is being used.
 */
cose_result cose_decode_not_encrypted(bytes *msg, bytes *external_aad,
    uint8_t *calculated_sig_buf, size_t calculated_sig_size,
    cose_sign1_mac_msg *out) {

    CborParser parser;
    CborValue val;
    cbor_parser_init(msg->buf, msg->len, 0, &parser, &val);

    // Validate
    CborError err = cbor_value_validate(&val, 0);
    if (err != CborNoError) {
        return cose_err_cbor_invalid;
    }

    CborTag tag =
        out->tag; // tag is optional, default: set from output structure
    if (cbor_value_is_tag(&val)) { // if present, get tag for CBOR
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
    cose_header_init(&unprotected);
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
    // Assign values to output structrure
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
    size_t sign_len;

    // Create MAC structure and encode it
    cose_encode_mac_structure("MAC0",
        &msg->protected_header,
        external_aad,
        &msg->payload,
        sign_buf,
        sizeof(sign_buf),
        &sign_len);

    // Apply MAC
    bytes sign = {sign_buf, sign_len};
    byte hmac_digest[HMAC_SHA256_DIGEST_SIZE];
    hmac_sign(secret, &sign, hmac_digest);

    // Prepare encoder and write Cbor tag
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, CborCOSE_Mac0Tag);

    // Encode COSE_Sign1 structure
    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);
    cbor_encode_byte_string(
        &ary, msg->protected_header.buf, msg->protected_header.len);
    cose_encode_header(&ary, &msg->unprotected_header);
    cbor_encode_byte_string(&ary, msg->payload.buf, msg->payload.len);
    cbor_encode_byte_string(&ary, hmac_digest, SHA256_DIGEST_SIZE);
    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
    return cose_ok;
}

/**
 * Encode a COSE_Mac0 message
 */
cose_result cose_encode_sign1(cose_sign1_mac_msg *msg, cose_alg_t alg,
    bytes *external_aad, cose_ecc_key *private_key, uint8_t *out,
    size_t out_size, size_t *out_len) {
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

    // Import key
    ecc_key key;
    wc_ecc_init(&key);
    wc_ecc_import_raw_ex(&key,
        private_key->x,
        private_key->y,
        private_key->d,
        (ecc_curve_id)private_key->curve_id); // (!)

    // Check key
    if (wc_ecc_check_key(&key) != MP_OKAY) {
        return cose_err_invalid_key;
    }

    // Calculate signature
    mp_int r; // destination for r component of signature.
    mp_int s; // destination for s component of signature.
    mp_init(&r);
    mp_init(&s);
    bytes to_sign = {to_sign_buf, to_sign_len};

    // Sign message
    if (alg == COSE_ALG_ES256) {
        sign_es256(&to_sign, &key, &r, &s);
    } else {
        return cose_err_unsupported;
    }

    // Convert signature R, S components to binary strings
    int key_size = wc_ecc_size(&key);
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

    // Prepare encoder and write CBOR tag
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, CborCOSE_Sign1Tag);

    // Encode COSE_Mac0 structure
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

/**
 * Verify cose sign1 message
 */
bool cose_verify_sign1(cose_ecc_key public_key, uint8_t *msg_buf, size_t msg_len, cose_sign1_mac_msg* out_decoded_msg) {
    cose_result res;
    assert(msg_buf != NULL);

    ecc_key ecc_key;
    wc_ecc_import_raw_ex(&ecc_key, public_key.x, public_key.y, public_key.d, public_key.curve_id);

    int check = wc_ecc_check_key(&ecc_key);
    assert(check == MP_OKAY);

    cose_sign1_mac_msg signed_msg;

    // Decode CBOR message
    bytes msg_bytes = {msg_buf, msg_len};
    uint8_t to_verify_buf[1024];
    res = cose_decode_not_encrypted(
        &msg_bytes, NULL, to_verify_buf, sizeof(to_verify_buf), &signed_msg);
    assert(res == cose_ok);

    // Decode protected header
    cose_header decoded_protected_header;
    cose_header_init(&decoded_protected_header);
    cose_decode_header_bytes(
        &signed_msg.protected_header, &decoded_protected_header);

    // Get header values for algorithm
    cose_header_value *alg_protected =
        cose_header_get(&decoded_protected_header, cose_label_alg);
    cose_header_value *alg_unprotected =
        cose_header_get(&signed_msg.unprotected_header, cose_label_alg);

    char *to_be_signed_hex;
    buffer_to_hexstring(
        &to_be_signed_hex, signed_msg.to_verify.buf, signed_msg.to_verify.len);

    char *signature_hex;
    buffer_to_hexstring(
        &signature_hex, signed_msg.signature.buf, signed_msg.signature.len);

    char *sig_hex;
    buffer_to_hexstring(
        &sig_hex, signed_msg.signature.buf, signed_msg.signature.len);

    // Verify message
    int verified = 0;
    if ((alg_protected != NULL && alg_protected->as_int == COSE_ALG_ES256) ||
        (alg_unprotected != NULL &&
            alg_unprotected->as_int == COSE_ALG_ES256)) {
        verified = verify_rs_es256(&signed_msg.to_verify, sig_hex, &ecc_key);
    }

    // Clean up allocated memory
    cose_header_free(&decoded_protected_header);

    // If a pointer to output struct is provided, fill output struct with decoded message
    if (out_decoded_msg != NULL) {
        *out_decoded_msg = signed_msg;
    }
    
    return verified == 1;
}