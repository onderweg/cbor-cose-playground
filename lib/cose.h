#ifndef ONDERWEG_COSE_H
#define ONDERWEG_COSE_H

#include <cbor.h>

typedef enum cose_alg_t {
    COSE_ALG_ES256 = -7,  // ECDSA w/ SHA-256
    COSE_ALG_HMAC_256 = 5 // HMAC w/ SHA-256
} cose_alg_t;

typedef int32_t cose_result;

typedef enum cose_result_t {
    cose_ok = 0,                // no error
    cose_err_cbor_invalid = 1,  // error in cbor validation
    cose_err_unsupported = 2,   // unsupported operation
    cose_err_unexpected = 3,    // unexpected value in cose structure
    cose_err_out_of_memory = 4, // cbor out of memory
    cose_err_invalid_key = 5    // invalid signing key
} cose_result_t;

typedef struct bytes {
    uint8_t *buf;
    size_t len;
} bytes;

/**
 * Cose header labels
 */
typedef enum cose_header_label {
    cose_label_alg = 1,
    cose_label_crit = 2,
    cose_label_content_type = 3,
    cose_label_KID = 4
} cose_header_label;

/**
 * Contains value of a cose header
 */
typedef union cose_header_value {
    int as_int;
    int64_t as_int64;
    uint64_t as_uint64;
    bytes as_bstr;
} cose_header_value;

/**
 * Represents a single item (label/value pair) in a COSE header set
 */
typedef struct cose_header_pair {
    int label;
    cose_header_value val;
} cose_header_pair;

/**
 * Represents a set of COSE header parameters.
 * 
 * The label/value pairs of the header parameters are stored in a 
 * dynamic (auto resized) array.
 */
typedef struct cose_header {
    cose_header_pair *pairs;
    int capacity;
    int size;
} cose_header;

/**
 * Structure representing a signed (COSE_Sign1) or MACed (COSE_Mac0) message
 *
 * See:
 * - COSE_Sign1:
 * https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-signing-objects
 * - COSE_Mac0:
 * https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-maced-messages-with-implici
 */
typedef struct cose_sign1_mac_msg {
    CborTag tag;
    bytes protected_header;
    cose_header unprotected_header;
    bytes payload;
    bytes signature;
    bytes to_verify;
} cose_sign1_mac_msg;

/**
 * Contains components of a public or private Elliptic curve cryptography (ECC) key
 * An ECC key is contains cNID value (curve-ID), scalar (d), and Point (x,y).
 */
typedef struct cose_ecc_key {
    // ecc point (public part)
    char *x;
    char *y;
    // ecc scalar (private part)
    char *d;
    // ecc curve id
    int curve_id; 
} cose_ecc_key;

void cose_header_init(cose_header *hdr);
void cose_header_push(cose_header *hdr, int label, cose_header_value value);
cose_header_value *cose_header_get(cose_header *hdr, int label);

void cose_header_free(cose_header *hdr);
void cose_sign1_mac_msg_free(cose_sign1_mac_msg* msg);


void cose_encode_header_bytes(
    cose_header *hdr, uint8_t *out, size_t out_size, size_t *out_len);
void cose_encode_header(CborEncoder *enc, cose_header *hdr);

cose_result cose_decode_header_bytes(bytes *protected, cose_header *out);
cose_result cose_decode_header(CborValue *cborValue, cose_header *out);

cose_result cose_decode_not_encrypted(bytes *msg, bytes *external_aad,
    uint8_t *calculated_sig_buf, size_t calculated_sig_size,
    cose_sign1_mac_msg *out);

cose_result cose_init_mac0(bytes *payload, cose_sign1_mac_msg *out_msg);
cose_result cose_encode_mac0(cose_sign1_mac_msg *msg, bytes *external_aad,
    bytes *secret, uint8_t *out, size_t out_size, size_t *out_len);

cose_result cose_encode_sign1(cose_sign1_mac_msg *msg, cose_alg_t alg,
    bytes *external_aad, cose_ecc_key *private_key, uint8_t *out,
    size_t out_size, size_t *out_len);

bool cose_verify_sign1(cose_ecc_key public_key, uint8_t *msg_buf, size_t msg_len, cose_sign1_mac_msg* out_decoded_msg);

#endif // ONDERWEG_COSE_H