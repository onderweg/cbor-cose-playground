#ifndef ONDERWEG_COSE_H
#define ONDERWEG_COSE_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>

#define COSE_ALG_ES256 -7   // ECDSA w/ SHA-256
#define COSE_ALG_HMAC_256 5 // HMAC w/ SHA-256

typedef struct bytes
{
    uint8_t *buf;
    size_t len;
} bytes;

typedef struct cose_protected_header
{
    int alg;               // index 1
    uint64_t content_type; // index 3
} cose_protected_header;

/**
 * Structure representing a signed (COSE_Sign1) or MACed (COSE_Mac0) message
 * 
 * See:
 * - COSE_Sign1: https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-signing-objects
 * - COSE_Mac0: https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-maced-messages-with-implici
 */
typedef struct cose_sign1_mac_msg
{    
    CborTag tag;
    bytes protected_header;
    bytes unprotected_header;
    bytes payload;
    bytes signature; 
    bytes to_verify; 
} cose_sign1_mac_msg;

void cose_decode_protected_hdr(bytes *protected, cose_protected_header *out);

void cose_decode_sign1_mac0(bytes *sign1, uint8_t *calculated_sig_buf, size_t calculated_sig_size, cose_sign1_mac_msg *out);

void cose_encode_mac0(cose_sign1_mac_msg* sign1, byte* secret, size_t secret_size,
                        uint8_t* out, size_t out_size, size_t* out_len);

int verify_hmac(bytes *to_verify, bytes *signature, size_t secret_len, const byte *secret);
int verify_es256(bytes *to_verify, bytes *signature, ecc_key *key);

#endif //ONDERWEG_COSE_H