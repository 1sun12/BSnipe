/**
 * @file pcapw.h
 * @brief Writing captured frames straight out as a real `.pcap` file
 * @note Called `pcapw` ("pcap writer") rather than just `pcap` on purpose. If this project ever
 *       links against libpcap for Monitor Mode, a header of ours named `pcap.h` would shadow
 *       libpcap's own and cause a very confusing afternoon
 */
#ifndef PCAPW_H
#define PCAPW_H

/**
 * @brief User headers:
 * - debug.h    |   helpful debugging macros
 */
#include "debug.h"

/**
 * @brief General headers:
 * - stdio.h    |   Standard I/O (FILE, fopen, fwrite, fclose)
 * - stdlib.h   |   General utilities (calloc, free)
 * - stdint.h   |   Fixed-width integers, which the pcap format is entirely made of
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * @brief Nou pcap constants
 * - PCAPW_FILENAME     |   Where the capture gets written
 * - PCAPW_MAGIC        |   Written in host byte order; a reader compares what it sees against
 *                          this value and works out our endianness from which way round it landed,
 *                          which is why nothing in this file ever needs byte swapping
 * - PCAPW_SNAPLEN      |   Longest frame we would ever store, matches MAX_FRAME_SIZE in sock.h
 * - PCAPW_LINKTYPE_*   |   (1) means "the bytes start at an Ethernet header", which is what we save
 */
#define PCAPW_FILENAME "capture.pcap"
#define PCAPW_MAGIC 0xA1B2C3D4
#define PCAPW_VERSION_MAJOR 2
#define PCAPW_VERSION_MINOR 4
#define PCAPW_SNAPLEN 65535
#define PCAPW_LINKTYPE_ETHERNET 1

/**
 * @brief The (24) byte header sitting at the very front of a .pcap file, written exactly once
 */
typedef struct pcapw_file_hdr_t pcapw_file_hdr_t;
struct pcapw_file_hdr_t {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;       // ~ Correction from GMT to local time; in practice everyone writes (0)
    uint32_t sigfigs;       // ~ Accuracy of the timestamps; also always (0) in practice
    uint32_t snaplen;
    uint32_t network;       // ~ The link type, telling the reader what the frame bytes actually are
};

/**
 * @brief The (16) byte header written in front of every single captured frame
 */
typedef struct pcapw_rec_hdr_t pcapw_rec_hdr_t;
struct pcapw_rec_hdr_t {
    uint32_t ts_sec;        // ~ When we caught it, whole seconds since the epoch
    uint32_t ts_usec;       // ~ ...and the leftover microseconds
    uint32_t incl_len;      // ~ How many bytes of the frame we actually saved into the file
    uint32_t orig_len;      // ~ How long the frame was out on the wire
};

/**
 * @brief Represents an open .pcap file being written to, and the count of what went in
 */
typedef struct pcapw_t pcapw_t;
struct pcapw_t {
    FILE *file;
    const char *filename;
    unsigned long frames_written;

    void (*open)(pcapw_t *self);
    void (*write)(pcapw_t *self, const void *frame, size_t len);
    void (*close)(pcapw_t *self);
    void (*destroy)(pcapw_t **self_ptr);
};

/**
 * ==========================================================================
 * Constructor & Destructor - Initialize and freeing "this" object
 * ==========================================================================
 * @note First param is always "this" object (self)
 */

/**
 * @brief Creates and initializes a nou pcap writer (constructor)
 * @return Pointer to nou pcap writer, or NULL on failure
 */
pcapw_t *pcapw_create(void);

/**
 * @brief Destroys and frees a nou pcap writer (destructor)
 * @param self_ptr Address of `this` object
 */
void pcapw_destroy(pcapw_t **self_ptr);

/**
 * ==========================================================================
 * METHODS - Functions that operate on the object
 * ==========================================================================
 * @note First param is always "this" object (self)
 */

/**
 * @brief Opens the file and lays down the (24) byte header that every .pcap starts with
 * @param self `This` object
 */
void pcapw_open(pcapw_t *self);

/**
 * @brief Writes one captured frame, stamped with the time right now
 * @param self `This` object
 * @param frame The raw ethernet frame, starting at the destination MAC
 * @param len How many bytes of it there are
 */
void pcapw_write(pcapw_t *self, const void *frame, size_t len);

/**
 * @brief Closes the file, if one was ever opened
 * @param self `This` object
 */
void pcapw_close(pcapw_t *self);

#endif
