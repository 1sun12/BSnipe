#ifndef OUTPUT_H
#define OUTPUT_H

#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define OUTPUT_FILENAME "dump.txt"      // ~ The human-readable capture log
#define FRAME_FILENAME "frames.txt"     // ~ Machine-readable frame hex, ready for text2pcap

typedef struct output_t output_t;
struct output_t {
    FILE *file;
    const char *filename;   // ~ Which file `open_file` should open; defaults to OUTPUT_FILENAME
    int to_file;
    int to_terminal;

    void (*open_file)(output_t *self);
    void (*close_file)(output_t *self);
    void (*writef)(output_t *self, const char *format, ...);
    void (*destroy)(output_t **self_ptr);
};

output_t *output_create(void);

void output_destroy(output_t **self_ptr);

void output_open_file(output_t *self);

void output_close_file(output_t *self);

void output_writef(output_t *self, const char *format, ...);

#endif
