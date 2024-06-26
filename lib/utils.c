#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

unsigned char* buffer_from_file(const char* filename, size_t* buffer_size) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Error: Unable to open file %s\n", filename);
        return NULL;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // Allocate memory for the buffer
    unsigned char* buffer = (unsigned char*)malloc(file_size);
    if (buffer == NULL) {
        printf("Error: Unable to allocate memory\n");
        fclose(file);
        return NULL;
    }

    // Read the file into the buffer
    size_t bytes_read = fread(buffer, sizeof(unsigned char), file_size, file);
    if (bytes_read != file_size) {
        printf("Error: Unable to read the entire file\n");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);

    // Set the buffer size if requested
    if (buffer_size != NULL) {
        *buffer_size = file_size;
    }

    return buffer;
}

size_t hexstring_to_buffer(uint8_t **buffer, char *string, size_t string_len) {
    size_t out_length = string_len / 2;
    uint8_t *block = malloc(out_length);

    for (unsigned int i = 0; i < out_length; i++) {
        char buf[3] = {string[2 * i], string[2 * i + 1], 0};
        block[i] = strtol(buf, 0, 16);
    }

    *buffer = block;
    return out_length;
}

size_t buffer_to_hexstring(char **string, uint8_t *buffer, size_t buf_len) {
    size_t out_len = 2 * buf_len + 1;
    char *block = malloc(out_len);
    char *p = block;

    for (int i = 0; i < buf_len; i++) {
        p += sprintf(p, "%02x", buffer[i]);
    }
    block[out_len - 1] = 0;

    *string = block;
    return out_len;
}

void phex(uint8_t *ary, size_t len) {
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x", ary[i]);
    }
    printf("\n");
}

void slice_str(const char *str, char *buffer, size_t start, size_t end) {
    size_t j = 0;
    for (size_t i = start; i <= end; ++i) {
        buffer[j++] = str[i];
    }
    buffer[j] = 0;
}