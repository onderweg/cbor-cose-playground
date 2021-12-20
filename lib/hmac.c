#include <stdio.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "hmac.h"
#include "utils.h"

/**
 * Sign byte buffer with HMAC 256
 */
void hmac_sign(bytes *secret, bytes *sign,
    uint8_t hmac_digest_out[HMAC_SHA256_DIGEST_SIZE]) {
    Hmac hmac;
    wc_HmacSetKey(&hmac, WC_SHA256, secret->buf, secret->len);
    wc_HmacUpdate(&hmac, sign->buf, sign->len);
    wc_HmacFinal(&hmac, hmac_digest_out);
}

/**
 * Compare calculated HMAC 256 signature to the provided signature.
 *
 * Returns 1 when signature is valid, 0 if invalid
 */
int hmac_verify(bytes *to_verify, bytes *signature, bytes *secret) {
    Hmac hmac;
    byte hmac_digest[SHA256_DIGEST_SIZE];
    wc_HmacSetKey(&hmac, WC_SHA256, secret->buf, secret->len);
    wc_HmacUpdate(&hmac, to_verify->buf, to_verify->len);
    wc_HmacFinal(&hmac, hmac_digest);
    // Compare calculated signature with signature in message
    int ret = memcmp(hmac_digest, signature->buf, SHA256_DIGEST_SIZE);
    return (ret == 0);
}