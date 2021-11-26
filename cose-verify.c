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

typedef struct cose_raw_msg
{
    bytes payload;
    bytes protected_header;
    bytes unprotected_header;
    bytes signature;   
    bytes to_verify; 
} cose_raw_msg;

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
 * Encodes COSE MAC_structure structure message structure in CBOR.
 * See: https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-how-to-compute-and-verify-a
 */
void cose_mac0_structure(const char *context,
                          bytes *body_protected,
                          bytes *external_aad,
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
    cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);
    cbor_encode_byte_string(&ary, payload->buf, payload->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out); 
}

/**
 * Encodes COSE Sig_structure structure in CBOR.
 * See: https://www.ietf.org/id/draft-ietf-cose-rfc8152bis-struct-15.html#name-signing-and-verification-pr
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
 * Compare calculated HMAC 256 signature with received signature
 */
int verify_hmac(bytes *to_verify, bytes *signature, size_t secret_len, const byte *secret)
{
    Hmac hmac;
    byte hmacDigest[SHA256_DIGEST_SIZE];

    wc_HmacSetKey(&hmac, WC_SHA256, secret, secret_len);

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
 * Decode sign1 message and calculate bytes to be verified
 */
void cose_decode_sign1(bytes *sign1, uint8_t *calculated_sig_buf, size_t calculated_sig_size, cose_raw_msg *out)
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

    // Get signature (sign1) or tag (mac0)
    bytes signature;
    cbor_value_dup_byte_string(&e, &signature.buf, &signature.len, &e);

    // Calculate bytes to verify. 
    size_t to_verify_len = 0;
    if (tag == 18) {
        // sign 1
        cose_sign1_structure(
            "Signature1", 
            &protected, 
            &unprotected, 
            &payload, 
            calculated_sig_buf, 
            calculated_sig_size, 
            &to_verify_len
        );
    } else if (tag == 17) {
        // mac0
        bytes external_aad ={NULL, 0};
        cose_mac0_structure(
            "MAC0", 
            &protected, 
            &external_aad, 
            &payload,
            calculated_sig_buf, 
            calculated_sig_size, 
            &to_verify_len
        );
    }
    bytes to_verify = (bytes){calculated_sig_buf, to_verify_len};

    out->payload = payload;
    out->protected_header = protected;
    out->unprotected_header = unprotected;
    out->signature = signature;
    out->to_verify = to_verify;
}

int main(int argc, char *argv[])
{
    cose_raw_msg signed_msg;
    byte *msg_buf, *key_buf;

    // Example HMAC-SHA256 signed COSE message    
    // Source: // Source: https://github.com/cose-wg/Examples/blob/3221310e2cf50ad13213daa7ca278209a8bc85fd/mac0-tests/HMac-01.json
    char *msg_hex = "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58";    
    char *key_hex = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188";

    // Convert message and key hex strings to bytes
    size_t key_len = hexstring_to_buffer(&key_buf, key_hex, strlen(key_hex));
    size_t msg_len = hexstring_to_buffer(&msg_buf, msg_hex, strlen(msg_hex));

    bytes msg_bytes = {msg_buf, msg_len};
    uint8_t to_verify_buf[1024];
    cose_decode_sign1(&msg_bytes, to_verify_buf, sizeof(to_verify_buf), &signed_msg);   

    // Verify signature    
    cose_protected_header protected_header = {
        .alg = 0};
    cose_parse_protected_hdr(&signed_msg.protected_header, &protected_header);    

    printf("Signature type in protected header: %i\n", protected_header.alg);
    if (protected_header.alg == COSE_ALG_HMAC_256)
    {        
        int verified = verify_hmac(
            &signed_msg.to_verify,
            &signed_msg.signature,
            key_len,
            key_buf);
        printf("Verified: %s\n", verified == 0 ? "YES" : "NO");
    }
}