#pragma once

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>

void phex(byte* ary, size_t len);

size_t buffer_to_hexstring(char** string, byte* buffer, size_t buf_len);
size_t hexstring_to_buffer(byte** buffer, char* string, size_t string_len);
void slice_str(const char * str, char * buffer, size_t start, size_t end);