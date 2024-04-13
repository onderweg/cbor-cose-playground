#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "cose.h"
#include "utils.h"

cose_ecc_key cose_pubkey_from_ecc(ecc_key key, char *x_buff, char *y_buff) {
    assert(x_buff != NULL);
    assert(y_buff != NULL);

    mp_int *raw_x = key.pubkey.x;
    mp_int *raw_y = key.pubkey.y;

    // Prepare new cose_ecc_key struct
    cose_ecc_key pk_ = {
        .x = x_buff,
        .y = y_buff,
        .d = NULL,
        .curve_id = ECC_SECP256R1,
    };

    mp_tohex(raw_x, (char *)x_buff);
    mp_tohex(raw_y, (char *)y_buff);

    mp_clear(raw_x);
    mp_clear(raw_y);

    return pk_;
}

int ecc_key_to_der_file(const char *fileName, ecc_key key) {
    uint8_t der_key[4096];    
    int ret = wc_EccKeyToDer(&key, der_key, 4096);
    if (ret < 0) {
        return -1;
    }

    FILE *fp;

    // writing prive key
    fp = fopen(fileName, "w");
    if (!fp) {
        return -1;
    }
    fwrite(der_key, ret, 1, fp);
    fclose(fp);
    return 0;
}

/**
 * Returns ecc key from a PEM key file. Sets `err` on error.
 */
ecc_key ecc_pubkey_from_pem(const char *fileName, int *err) {
    int ret = 0;
    ecc_key pubkey;

    wc_ecc_init(&pubkey);

    // Loads a PEM key from a file and converts to a DER encoded buffer.
    unsigned char der[1024];
    ret = wc_PemPubKeyToDer(fileName, der, sizeof(der));
    if (ret < 0) {
        if (err != NULL)
            *err = ret;
        return pubkey;
    }

    word32 idx = 0;
    ret = wc_EccPublicKeyDecode(der, &idx, &pubkey, sizeof(der));
    if (ret != 0) {
        if (err != NULL)
            *err = ret;
        return pubkey;
    }
    return pubkey;
}

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
    // Signature is R and L concatenated, so length should be 2 * key size,
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
 * Calculate digest of message to sign, and signs the digest with a ECDSA
 * signature. Produces R and S components.
 */
void sign_es256(
    bytes *to_sign, ecc_key *private_key, mp_int *r_out, mp_int *s_out) {
    WC_RNG rng;
    wc_InitRng(&rng);
    // Compute SHA256 digest
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    wc_InitSha256(&sha);
    int res = wc_Sha256Update(&sha, to_sign->buf, (word32)to_sign->len);
    assert(res == 0);
    res = wc_Sha256Final(&sha, digest);
    assert(res == 0);
    // Sign message digest
    res = wc_ecc_sign_hash_ex(
        digest, sizeof(digest), &rng, private_key, r_out, s_out);
    assert(res == MP_OKAY);
}