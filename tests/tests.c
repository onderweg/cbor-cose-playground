#include <stdio.h>

#include <cbor.h>
#include <cose.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>

#define TEST_COLOR_BOLD "\033[1m"
#define TEST_COLOR_RESET "\033[0m"
#define TEST_COLOR_SUCCESS "\033[32m"
#define TEST_COLOR_FAIL "\033[31m"
#define TEST_COLOR_MAYBE "\033[35m"

/* The following lines make up our testing "framework" :) */
static int fails = 0;

#define test(_s)                                                               \
    { printf("✪ %s ✪\n", _s); }
#define test_cond(_c, _n)                                                      \
    if (_c)                                                                    \
        printf("  " TEST_COLOR_SUCCESS "✓ PASSED" TEST_COLOR_RESET "\n");      \
    else {                                                                     \
        printf("  " TEST_COLOR_FAIL "✕ FAILED on line %i %s" TEST_COLOR_RESET  \
               "\n",                                                           \
            __LINE__,                                                          \
            _n);                                                               \
        fails++;                                                               \
    }

void leak() {
    cose_header header;
    cose_header_init(&header);
    cose_header_push(
        &header, cose_label_alg, (cose_header_value){ .as_int = 25 });
}

void test_encodes_header() {
    test("Encodes header");
    cose_header header;
    cose_header_init(&header);
    cose_header_push(
        &header, cose_label_alg, (cose_header_value){ .as_int = 25 });
    cose_header_push(&header,
        cose_label_KID,
        (cose_header_value){ .as_bstr = { (uint8_t *)"11", 2 } });
    test_cond(header.size == 2, "header size");
    cose_header_value *pair = cose_header_get(&header, cose_label_alg);
    test_cond(pair->as_int == 25, "header value");	
}

void test_decodes_header() {
    test("Decodes header");
    byte buf[] = { 0xa2, 0x01, 0x02, 0x03, 0x04 }; //  {1: 2, 3: 4}
    bytes input = { buf, sizeof(buf) };
    cose_header header;
    cose_header_init(&header);
    cose_result res = cose_decode_protected_header(&input, &header);
    test_cond(res == cose_ok, "");

    cose_header_value *pair1 = cose_header_get(&header, 1);
    cose_header_value *pair2 = cose_header_get(&header, 3);
    test_cond(pair1->as_int == 2, "");
    test_cond(pair2->as_int == 4, "");
}

int main(int argc, char **argv) {
    test_encodes_header();
    test_decodes_header();

    if (fails) {
        printf("\n*** %d TESTS %sFAILED%s ***\n",
            fails,
            TEST_COLOR_FAIL TEST_COLOR_BOLD,
            TEST_COLOR_RESET);
        return 1;
    }

    printf("\n*** ALL TESTS %sPASSED%s ***\n",
        TEST_COLOR_SUCCESS TEST_COLOR_BOLD,
        TEST_COLOR_RESET);

    return 0;
}
