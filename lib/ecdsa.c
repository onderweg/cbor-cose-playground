#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include "cose.h"
#include "utils.h"

/**
 * Verify ES256 (SHA256 with ECDSA) signature.
 * Signature is expected to be DER-encoded ECDSA ASN format.
 *
 * Returns 1 when signature is valid, 0 if invalid
 */
int verify_der_es256(bytes *to_verify, bytes *signature, ecc_key *public_key) {
    // Compute digest
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    wc_InitSha256(&sha);
    int res = wc_Sha256Update(&sha, to_verify->buf, (word32)to_verify->len);
    assert(res == 0);
    res = wc_Sha256Final(&sha, digest);
    assert(res == 0);
    // Verify
    int verified = 0;
    res = wc_ecc_verify_hash((const byte *)signature->buf,
        signature->len,
        digest,
        sizeof(digest),
        &verified,
        public_key);
    assert(res == 0);
    return verified;
}

/**
 * Verify ES256 (SHA256 with ECDSA) signature.
 * Signature is expected to be hex string, with concatened R and S components.
 *
 * Returns 1 when signature is valid, 0 if invalid
 */
int verify_rs_es256(bytes *to_verify, char *sig_hex, ecc_key *public_key) {
    assert(sig_hex != NULL);
    int key_size = wc_ecc_size(public_key);
    // Check signature length
    // Signature is R and L concatenated, so length sould be 2 * key size,
    // times 2 (because hex encoded: 2 chars per byte)
    assert(strlen(sig_hex) == 2 * 2 * key_size);

    int sig_len = strlen(sig_hex);
    // Split hex string into R and S components.
    char r[1 + key_size * 2];
    char s[1 + key_size * 2];
    slice_str((const char *)sig_hex, r, 0, (sig_len / 2) - 1);
    slice_str((const char *)sig_hex, s, sig_len / 2, sig_len + 1);
    // Convert R and S components into a DER-encoded ECDSA signature.
    byte der_sig_buf[512];
    word32 der_sig_len = sizeof(der_sig_buf);
    int res = wc_ecc_rs_to_sig(r, s, der_sig_buf, &der_sig_len);
    assert(res == 0);
    bytes der_sig = {der_sig_buf, der_sig_len};
    return verify_der_es256(to_verify, &der_sig, public_key);
}

/**
 * Calculate digest of message to sign, and signs the digest with a ECDSA signature.
 * Produces R and S components.
 */
void sign_es256(bytes *to_sign, ecc_key *private_key, mp_int *r, mp_int *s) {    
    WC_RNG rng;
    wc_InitRng(&rng);
    // Compute digest
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    wc_InitSha256(&sha);
    int res = wc_Sha256Update(&sha, to_sign->buf, (word32)to_sign->len);
    assert(res == 0);
    res = wc_Sha256Final(&sha, digest);
    assert(res == 0);
    // Sign message
    res = wc_ecc_sign_hash_ex(digest, sizeof(digest), &rng, private_key, r, s);
    assert(res == MP_OKAY);
}