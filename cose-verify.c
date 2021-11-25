#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include "wolfssl/wolfcrypt/sha256.h"

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

typedef struct cose_msg
{
    bytes payload;
    cose_protected_header protected_header;
    bytes unprotected_header;
    bytes signature;   
    bytes calculated_signature; 
} cose_msg;

size_t hexstring_to_buffer(byte **buffer, char *string, size_t string_len)
{
    size_t out_length = string_len / 2;
    byte *block = malloc(out_length);

    for (unsigned int i = 0; i < out_length; i++)
    {
        char buf[3] = {string[2 * i], string[2 * i + 1], 0};
        block[i] = (byte)strtol(buf, 0, 16);
    }

    *buffer = block;
    return out_length;
}

size_t buffer_to_hexstring(char **string, byte *buffer, size_t buf_len)
{
    size_t out_len = 2 * buf_len + 1;
    char *block = malloc(out_len);
    char *p = block;

    for (int i = 0; i < buf_len; i++)
    {
        p += sprintf(p, "%02x", buffer[i]);
    }
    block[out_len - 1] = 0;

    *string = block;
    return out_len;
}

/**
 * CBOR encodes the structure of a signed message
 */
void cose_sign1_structure(const char *context,
                          bytes *body_protected,
                          bytes *unprotected,
                          bytes *payload,
                          uint8_t *out,
                          size_t out_size,
                          size_t *out_len)
{
    CborEncoder enc;    
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_text_stringz(&ary, context);
    cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);

    cbor_encode_byte_string(&ary, unprotected->buf, unprotected->len);
    cbor_encode_byte_string(&ary, payload->buf, payload->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

/**
 * Parse cose protected header into a struct
 */
void cose_parse_protected_hdr(bytes *protected, cose_protected_header *out)
{
    CborParser parser;
    CborValue cborValue;
    cbor_parser_init(protected->buf, protected->len, 0, &parser, &cborValue);

    CborValue map;
    cbor_value_enter_container(&cborValue, &map);
    int key;
    while (!cbor_value_at_end(&map))
    {
        // We expect integer keys in the protected header
        if (!cbor_value_is_integer(&map))
        {
            return;
        }
        // Get key
        cbor_value_get_int_checked(&map, &key);
        cbor_value_advance_fixed(&map);
        if (key == 1) // alg
        {
            cbor_value_get_int_checked(&map, &out->alg);            
            cbor_value_advance_fixed(&map);
        }
        else if (key == 3)
        { // content type
            cbor_value_get_uint64(&map, &out->content_type);            
            cbor_value_advance_fixed(&map);
        }
    }
    cbor_value_leave_container(&cborValue, &map);
}

/**
 * Compare calculated HMAC 256 signature hash with received signature
 */
int verify_hmac(bytes *to_verify, bytes *signature, char *secret)
{
    Hmac hmac;
    byte hmacDigest[SHA256_DIGEST_SIZE];

    wc_HmacSetKey(&hmac, WC_SHA256, (const byte *)secret, strlen(secret));

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

int verify_es256(bytes *to_verify, bytes *signature, ecc_key *key)
{
    // Compute digest
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, to_verify->buf, (word32)to_verify->len);
    wc_Sha256Final(&sha, digest);

    int ret, verified = 0;
    ret = wc_ecc_verify_hash(signature->buf, (word32)signature->len, digest, sizeof(digest), &verified, key);

    return verified;
}

/**
 * Decode sign1 message and calculate expected signature
 */
void cose_decode_sign1(bytes *sign1, uint8_t *calculated_sig_buf, size_t calculated_sig_size, cose_msg *out)
{
    // Parse
    CborParser parser;
    CborValue val;
    cbor_parser_init(sign1->buf, sign1->len, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    // Get protected header
    bytes protected;
    cbor_value_dup_byte_string(&e, &protected.buf, &protected.len, &e);

    // Parse protected header
    cose_protected_header protected_header = {
        .alg = 0};
    cose_parse_protected_hdr(&protected, &protected_header);

    // Get unprotected header, if not empty
    bytes unprotected = {NULL, 0};
    if (cbor_value_is_byte_string(&e))
    {                
        cbor_value_dup_byte_string(&e, &unprotected.buf, &unprotected.len, &e);
    }
    else
    {
        cbor_value_advance(&e); // skip unprotected header
    }

    // Get payload
    bytes payload;    
    cbor_value_dup_byte_string(&e, &payload.buf, &payload.len, &e);

    // Get signature
    bytes signature;
    cbor_value_dup_byte_string(&e, &signature.buf, &signature.len, &e);

    // Calculate signature to verify    
    size_t to_verify_len;
    cose_sign1_structure(
        "Signature1", 
        &protected, 
        &unprotected, 
        &payload, 
        calculated_sig_buf, 
        calculated_sig_size, 
        &to_verify_len
    );
    bytes to_verify = (bytes){calculated_sig_buf, to_verify_len};

    out->payload = payload;
    out->protected_header = protected_header;
    out->unprotected_header = unprotected;
    out->signature = signature;
    out->calculated_signature = to_verify;
}

int main(int argc, char *argv[])
{
    cose_msg signed_msg;
    byte *msg_buf;

    // HMAC-SHA256 signed cose message    
    char *msg_hex = "d28445a201050300a04e546869732061206d657373616765582091e726b7d4897fdfdfff50652d977fdd3dbe3110d08059569ffbfa18978b281e";    

    size_t msg_len = hexstring_to_buffer(&msg_buf, msg_hex, strlen(msg_hex));
    bytes msg_bytes = {msg_buf, msg_len};
    uint8_t to_verify_buf[1024];
    cose_decode_sign1(&msg_bytes, to_verify_buf, sizeof(to_verify_buf), &signed_msg);   


    // Verify signature
    if (signed_msg.protected_header.alg == COSE_ALG_HMAC_256)
    {
        char* key = "vleuten";
        int verified = verify_hmac(
            &signed_msg.calculated_signature,
            &signed_msg.signature,
            key);
        printf("Verified: %s\n", verified == 0 ? "YES" : "NO");
    }
}