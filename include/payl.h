#ifndef PAYL_H
#define PAYL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define HEX_BYTES_PER_LINE 16                            // ~ One line of hex is equivalent to 0x10, then 0x20... and so on
#define HEX_LINE_SIZE (HEX_BYTES_PER_LINE * 3 + 1)       // ~ Every byte prints as "XX " (3 chars), and sprintf lays a NUL down after the last one

typedef struct output_t output_t;

typedef struct payl_t payl_t;
struct payl_t {
    uint8_t *shift;  // ~ Payload shifter (move -1 or +1 bytes across the payload)
    void *buffer;
    size_t payl_len;
    char hex_line[HEX_LINE_SIZE];

    // ~ Function pointers (I LOVE ABSTRACTION!!!! :DDDD)
    void (*parse)(payl_t *self, output_t *out);
    void (*set_buffer)(payl_t *self, void *buff, size_t total_len, size_t headers_len);
    void (*destroy)(payl_t **self_ptr);
};

payl_t *payl_create(void);

void payl_destroy(payl_t **self_ptr);

void payl_set_buffer(payl_t *self, void *buff, size_t total_len, size_t headers_len);

void payl_parse(payl_t *self, output_t *out);


#endif