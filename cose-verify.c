/* 
 * Verification test for HMAC-SHA256 (HS256) MAC'ed COSE message
 *
 */

#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include "lib/cose.h"
#include "lib/utils.h"

void verify_mac0() {
    cose_sign1_mac_msg signed_msg;
    byte *msg_buf, *key_buf;

    // Example HMAC-SHA256 signed COSE message    
    // Source: // Source: https://github.com/cose-wg/Examples/blob/3221310e2cf50ad13213daa7ca278209a8bc85fd/mac0-tests/HMac-01.json
    char *msg_hex = "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58";    
    char *key_hex = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188";

    // Convert message and key hex strings to bytes
    size_t key_len = hexstring_to_buffer(&key_buf, key_hex, strlen(key_hex));
    size_t msg_len = hexstring_to_buffer(&msg_buf, msg_hex, strlen(msg_hex));

    // Decode CBOR message
    bytes msg_bytes = {msg_buf, msg_len};
    uint8_t to_verify_buf[1024];
    cose_decode_sign1_mac0(&msg_bytes, to_verify_buf, sizeof(to_verify_buf), &signed_msg);   

    // Parse protected header    
    cose_protected_header protected_header = {
        .alg = 0};
    cose_decode_protected_header(&signed_msg.protected_header, &protected_header);    

    printf("CBOR tag: %llu\n", signed_msg.tag);
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

int main(int argc, char *argv[])
{
    verify_mac0();
}