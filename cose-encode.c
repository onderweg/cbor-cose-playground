/* 
 * Verification test for HMAC-SHA256 (HS256) MAC'ed COSE message
 *
 */

#include <stdio.h>
#include <string.h>

#include <cbor.h>

#include "lib/cose.h"
#include "lib/utils.h"

int main(int argc, char *argv[])
{
    byte secret[] = { 0xAB, 0xAC, 0xAD };
    size_t secret_size = sizeof(secret);

    // Encode payload
    byte *payload_buf;
    char* payload_hex = "684869207468657265"; // CBOR encoded text "Hi there"
    size_t payload_len = hexstring_to_buffer(&payload_buf, payload_hex, strlen(payload_hex));
    bytes payload = {payload_buf, payload_len};   
    
    // Encode protected header
    uint8_t protected_buf[512];
    size_t protected_len;
    cose_protected_header protected_header = {
        .alg = COSE_ALG_HMAC_256};    
    cose_encode_protected_header(
        &protected_header,
        protected_buf,
        512,
        &protected_len
    );
    bytes protected = {protected_buf, protected_len};    

    cose_sign1_mac_msg msg = {
        .payload = payload,
        .protected_header = protected,
        .unprotected_header = {NULL, 0}
    };    
    
    byte out_buf[512];
    size_t out_size = sizeof(out_buf);
    size_t out_len;

    cose_encode_mac0(
        &msg, 
        secret, 
        secret_size,
        out_buf, 
        out_size, 
        &out_len
    );

    // Print result
    for (int i = 0; i < out_len; i++)
    {
        printf("%02x", out_buf[i]);
    }
    printf("\n");      
}