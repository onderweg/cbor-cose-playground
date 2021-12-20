#ifndef ONDERWEG_HMAC_H
#define ONDERWEG_HMAC_H

#include "cose.h"

#ifndef HMAC_SHA256_DIGEST_SIZE
#define HMAC_SHA256_DIGEST_SIZE 32
#endif

int hmac_verify(bytes *to_verify, bytes *signature, bytes *secret);
void hmac_sign(bytes *secret, bytes *sign,
    uint8_t hmac_digest_out[HMAC_SHA256_DIGEST_SIZE]);

#endif // ONDERWEG_HMAC_H