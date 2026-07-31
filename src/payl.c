#include "debug.h"
#include "payl.h"
#include "output.h"

payl_t *payl_create(void) {
    OUTPUT_D_MSG("payl_create : Attempting to create a payload parser...");

    // ~ Create new payload parser object
    payl_t *new = NULL;

    // ~ Allocate memory + error check
    new = (payl_t *)calloc(1, sizeof(payl_t));
    if (new == NULL) {
        perror("\n[ERROR]:payl_create");
        return NULL;
    }

    // ~ Default fields
    new->shift = NULL; // ~ Does not need mallocation, will be pointing at existing memory
    
    // ~ Wire up those beautiful function pointers
    new->parse = payl_parse;
    new->parse_pcap = payl_parse_pcap;
    new->set_buffer = payl_set_buffer;
    new->destroy = payl_destroy;

    // ~ Return newly created object
    OUTPUT_D_MSG("payl_create : New payload parser successfully created!");
    return new;
}

void payl_destroy(payl_t **self_ptr) {
    does_exist(self_ptr);
    does_exist(*self_ptr);

    payl_t *self = *self_ptr;

    OUTPUT_D_MSG("payl_destroy : Payload parser being destroyed...");

    // ~ Deallocate this entire memory block
    // ~ `buffer` and `shift` both point at memory the socket owns, so they are not ours to free
    free(self);
    *self_ptr = NULL;

    OUTPUT_D_MSG("payl_destroy : Payload parser destroyed successfully!");
}

void payl_set_buffer(payl_t *self, void *buff, size_t total_len, size_t headers_len){
    does_exist(self);
    OUTPUT_D_MSG("payl_set_buffer : Attempting to set buffer info for the payload parser...");

    // ~ Point buffer to the location of the recieved packet
    self->buffer = buff;

    // ~ A packet that is all headers has no payload to dump, and subtracting here would
    // ~ wrap size_t around to something enormous, so bail out with an empty payload
    if (headers_len >= total_len) {
        self->payl_len = 0;
        self->shift = NULL;
        OUTPUT_D_MSG("payl_set_buffer : This packet carries no payload, nothing to dump.");
        return;
    }

    // ~ Calculate size of the payload portion of the packet (so we know when to stop and not overflow)
    // ~ PAYLOAD ONLY + NO HEADERS, otherwise we walk off the end of what recv() actually gave us
    self->payl_len = total_len - headers_len;

    // ~ Set our -1/+1 byte shifter at the beginning of the payload, were ready to go!
    self->shift = ((uint8_t *)self->buffer) + headers_len;

    OUTPUT_D_MSG("payl_set_buffer : Successfully set the buffer info for the payload parser!");
}

void payl_parse(payl_t *self, output_t *out) {
    does_exist(self);
    does_exist(out);
    OUTPUT_D_MSG("payl_parse : Attempting to hex-dump the payload...");

    // ~ Either nothing was handed to us, or the packet was pure headers with nothing behind them
    if (self->shift == NULL || self->payl_len == 0) {
        OUTPUT_D_MSG("payl_parse : There is no payload to hex-dump.");
        return;
    }

    // ~ The amount of bytes processed
    size_t bytes_proc = 0;

    while (bytes_proc < self->payl_len) {
        // ~ How many bytes belong on this line: a full (16), or just the leftovers on the final line
        size_t bytes_remain = self->payl_len - bytes_proc;
        size_t line_len = (bytes_remain < HEX_BYTES_PER_LINE) ? bytes_remain : HEX_BYTES_PER_LINE;

        // ~ Write at each byte in our string-hex-buffer (taking advantage of pointer arithmetic magic)
        char *write_at_addr_in_hex_line = self->hex_line;

        // ~ Construct the hex string one byte at a time
        // ~ NOTE: the payload index is (bytes_proc + i) and bytes_proc holds still until the line is
        // ~ finished. Nudging bytes_proc inside this loop would advance the index twice per byte,
        // ~ printing every other byte and reading past the end of the payload to do it
        for (size_t i = 0; i < line_len; i++) {
            size_t space_left = sizeof(self->hex_line) - (size_t)(write_at_addr_in_hex_line - self->hex_line);
            snprintf(write_at_addr_in_hex_line, space_left, "%02X ", self->shift[bytes_proc + i]);
            write_at_addr_in_hex_line += 3;
        }

        // ~ The line is built, now the counter is allowed to move
        bytes_proc += line_len;

        // ~ Print the hex parsed payload :]
        out->writef(out, "\n%s", self->hex_line);
    }

    OUTPUT_D_MSG("payl_parse : Successfully hex-dumped the entire payload!");
}

void payl_parse_pcap(payl_t *self, output_t *out) {
    does_exist(self);
    does_exist(out);
    OUTPUT_D_MSG("payl_parse_pcap : Attempting to hex-dump in text2pcap format...");

    // ~ Either nothing was handed to us, or the packet was pure headers with nothing behind them
    if (self->shift == NULL || self->payl_len == 0) {
        OUTPUT_D_MSG("payl_parse_pcap : There is nothing to hex-dump.");
        return;
    }

    // ~ The amount of bytes processed
    size_t bytes_proc = 0;

    while (bytes_proc < self->payl_len) {
        // ~ How many bytes belong on this line: a full (16), or just the leftovers on the final line
        size_t bytes_remain = self->payl_len - bytes_proc;
        size_t line_len = (bytes_remain < HEX_BYTES_PER_LINE) ? bytes_remain : HEX_BYTES_PER_LINE;

        char *write_at_addr_in_hex_line = self->hex_line;

        // ~ Every line opens with how far into the frame it starts. This is the whole reason this
        // ~ dumper exists: text2pcap reads an offset of zero as "a new packet starts here", so the
        // ~ frames keep themselves apart in the file without us writing any separator
        int offset_written = snprintf(write_at_addr_in_hex_line, sizeof(self->hex_line), "%0*zx  ", HEX_OFFSET_WIDTH, bytes_proc);
        if (offset_written < 0 || (size_t)offset_written >= sizeof(self->hex_line)) {
            OUTPUT_D_MSG("payl_parse_pcap : the offset column did not fit, stopping here.");
            return;
        }
        write_at_addr_in_hex_line += offset_written;

        // ~ Same rule as payl_parse: index off (bytes_proc + i) and leave bytes_proc where it is
        // ~ until the line is finished, or the index walks forward twice for every byte
        for (size_t i = 0; i < line_len; i++) {
            size_t space_left = sizeof(self->hex_line) - (size_t)(write_at_addr_in_hex_line - self->hex_line);
            snprintf(write_at_addr_in_hex_line, space_left, "%02x ", self->shift[bytes_proc + i]);
            write_at_addr_in_hex_line += 3;
        }

        // ~ The line is built, now the counter is allowed to move
        bytes_proc += line_len;

        out->writef(out, "%s\n", self->hex_line);
    }

    // ~ A blank line between frames; text2pcap does not need it, but it makes the file readable
    out->writef(out, "\n");

    OUTPUT_D_MSG("payl_parse_pcap : Successfully hex-dumped in text2pcap format!");
}
