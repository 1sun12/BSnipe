
#include "output.h"

output_t *output_create(void) {
    OUTPUT_D_MSG("output_create : Attempting to create an output handler...");

    output_t *new = NULL;

    if ((new = (output_t *)calloc(1, sizeof(output_t))) == NULL) {
        perror("\n[ERROR]:output_create");
        return NULL;
    }

    new->file = NULL;
    new->to_file = 0;
    new->to_terminal = 1;

    new->open_file = output_open_file;
    new->close_file = output_close_file;
    new->writef = output_writef;
    new->destroy = output_destroy;

    OUTPUT_D_MSG("output_create : Successfully created an output handler!");
    return new;
}

void output_destroy(output_t **self_ptr) {
    does_exist(self_ptr);
    does_exist(*self_ptr);

    output_t *self = *self_ptr;

    OUTPUT_D_MSG("output_destroy : Output handler being destroyed...");

    if (self->file != NULL) {
        fclose(self->file);
        self->file = NULL;
    }

    free(self);
    *self_ptr = NULL;

    OUTPUT_D_MSG("output_destroy : Output handler destroyed successfully!");
}

void output_open_file(output_t *self) {
    does_exist(self);
    OUTPUT_D_MSG("output_open_file : Attempting to open output file...");

    if (self->file != NULL) {
        fclose(self->file);
        self->file = NULL;
    }

    self->file = fopen(OUTPUT_FILENAME, "w");
    if (self->file == NULL) {
        perror("\n[ERROR]:output_open_file");
        return;
    }

    OUTPUT_D_MSG("output_open_file : Successfully opened output file!");
}

void output_close_file(output_t *self) {
    does_exist(self);
    OUTPUT_D_MSG("output_close_file : Attempting to close output file...");

    if (self->file != NULL) {
        fclose(self->file);
        self->file = NULL;
    }

    OUTPUT_D_MSG("output_close_file : Successfully closed output file!");
}

void output_writef(output_t *self, const char *format, ...) {
    does_exist(self);

    va_list args;

    if (self->to_terminal == 1) {
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }

    if (self->to_file == 1 && self->file != NULL) {
        va_start(args, format);
        vfprintf(self->file, format, args);
        va_end(args);
        fflush(self->file);
    }
}
