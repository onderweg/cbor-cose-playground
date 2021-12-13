#ifndef ONDERWG_ECDSA_H
#define ONDERWG_ECDSA_H

#include "cose.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>

int verify_rs_es256(bytes *to_verify, char* sig_hex, ecc_key *public_key);
int verify_der_es256(bytes *to_verify, bytes *signature, ecc_key *public_key);

#endif // ONDERWG_ECDSA_H
