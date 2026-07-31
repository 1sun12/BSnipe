#ifndef PAYL_H
#define PAYL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define HEX_BYTES_PER_LINE 16                            // ~ One line of hex is equivalent to 0x10, then 0x20... and so on
#define HEX_OFFSET_WIDTH 6                               // ~ How many digits the text2pcap offset column gets, e.g. "000000"

// ~ The buffer has to hold the longest line either dumper can build, which is the text2pcap one:
// ~ the offset, (2) spaces after it, then "xx " for every byte, then the NUL that snprintf lays down
#define HEX_LINE_SIZE (HEX_OFFSET_WIDTH + 2 + HEX_BYTES_PER_LINE * 3 + 1)

typedef struct output_t output_t;

typedef struct payl_t payl_t;
struct payl_t {
    uint8_t *shift;  // ~ Payload shifter (move -1 or +1 bytes across the payload)
    void *buffer;
    size_t payl_len;
    char hex_line[HEX_LINE_SIZE];

    // ~ Function pointers (I LOVE ABSTRACTION!!!! :DDDD)
    void (*parse)(payl_t *self, output_t *out);
    void (*parse_pcap)(payl_t *self, output_t *out);
    void (*set_buffer)(payl_t *self, void *buff, size_t total_len, size_t headers_len);
    void (*destroy)(payl_t **self_ptr);
};

payl_t *payl_create(void);

void payl_destroy(payl_t **self_ptr);

/**
 * @brief Points the parser at a region of the recieved packet
 * @param self `This` object
 * @param buff The socket's buffer, holding the frame that just came in
 * @param total_len How many bytes recv() actually handed us
 * @param headers_len Where the dump should start; pass (0) for the whole frame, or the combined
 *                    header length for the payload on its own
 */
void payl_set_buffer(payl_t *self, void *buff, size_t total_len, size_t headers_len);

/**
 * @brief Hex-dumps the region for a human to read, (16) bytes per line
 */
void payl_parse(payl_t *self, output_t *out);

/**
 * @brief Hex-dumps the region in `text2pcap` format, so it can become a real .pcap
 * @note Every line is an offset, (2) spaces, then up to (16) lowercase bytes. text2pcap treats an
 *       offset of zero as the start of a new packet, so frames delimit themselves
 */
void payl_parse_pcap(payl_t *self, output_t *out);


#endif