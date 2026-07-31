#include "pcapw.h"

#include <sys/time.h>

/*
 * ==========================================================================
 * Both structs get copied onto disk byte-for-byte, so any padding the compiler quietly
 * slipped between the fields would corrupt the file for every reader on earth. Neither
 * one needs padding on a sane platform, but this makes the build say so out loud rather
 * than letting a bad capture be the first hint that something moved.
 * ==========================================================================
 */
_Static_assert(sizeof(pcapw_file_hdr_t) == 24, "a .pcap file header must be exactly (24) bytes");
_Static_assert(sizeof(pcapw_rec_hdr_t) == 16, "a .pcap record header must be exactly (16) bytes");

/*
 * ==========================================================================
 * Constructor & Destructor - Initialize and freeing "this" object
 * ==========================================================================
 */

pcapw_t *pcapw_create(void) {
    OUTPUT_D_MSG("pcapw_create : Attempting to create a pcap writer...");

    // ~ Create a new pcap writer
    pcapw_t *new = NULL;

    // ~ Allocate however many bytes it needs and zero the entire space
    if ((new = (pcapw_t *)calloc(1, sizeof(pcapw_t))) == NULL) {
        perror("\n[ERROR]:pcapw_create");
        return NULL;
    }

    // ~ Load default values
    new->file = NULL;
    new->filename = PCAPW_FILENAME;
    new->frames_written = 0;

    // ~ Wire up function pointers
    new->open = pcapw_open;
    new->write = pcapw_write;
    new->close = pcapw_close;
    new->destroy = pcapw_destroy;

    // ~ Return the newly created writer
    OUTPUT_D_MSG("pcapw_create : Successfully created a pcap writer!");
    return new;
}

void pcapw_destroy(pcapw_t **self_ptr) {
    does_exist(self_ptr);
    does_exist(*self_ptr);

    pcapw_t *self = *self_ptr;

    OUTPUT_D_MSG("pcapw_destroy : Pcap writer being destroyed...");

    // ~ Never leave a half-written capture behind
    self->close(self);

    // ~ Deallocate this entire memory block
    free(self);
    *self_ptr = NULL;

    OUTPUT_D_MSG("pcapw_destroy : Pcap writer destroyed successfully!");
}

/*
 * ==========================================================================
 * METHODS - Functions that operate on the object
 * ==========================================================================
 */

void pcapw_open(pcapw_t *self) {
    does_exist(self);
    OUTPUT_D_MSG("pcapw_open : Attempting to open a pcap file...");

    // ~ Close whatever was open before, so starting a second capture cannot leak the first file
    if (self->file != NULL) {
        self->close(self);
    }

    if (self->filename == NULL) {
        self->filename = PCAPW_FILENAME;
    }

    // ~ "wb" because this is binary; on Linux the b changes nothing, but it says what we mean
    self->file = fopen(self->filename, "wb");
    if (self->file == NULL) {
        perror("\n[ERROR]:pcapw_open");
        return;
    }

    self->frames_written = 0;

    // ~ Every .pcap opens with this one header describing the whole file
    // ~ All of it goes down in host byte order on purpose; the magic number is what lets a reader
    // ~ figure out which order that was
    pcapw_file_hdr_t hdr;
    hdr.magic_number = PCAPW_MAGIC;
    hdr.version_major = PCAPW_VERSION_MAJOR;
    hdr.version_minor = PCAPW_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = PCAPW_SNAPLEN;
    hdr.network = PCAPW_LINKTYPE_ETHERNET;

    if (fwrite(&hdr, sizeof(hdr), 1, self->file) != 1) {
        perror("\n[ERROR]:pcapw_open");
        self->close(self);
        return;
    }

    OUTPUT_D_MSG("pcapw_open : Successfully opened a pcap file!");
}

void pcapw_write(pcapw_t *self, const void *frame, size_t len) {
    does_exist(self);
    does_exist(frame);

    // ~ Nothing to do if the file was never opened, or there is no frame to speak of
    if (self->file == NULL || len == 0) {
        return;
    }

    // ~ Stamp it with the time right now; this frame came off the wire microseconds ago
    struct timeval now;
    if (gettimeofday(&now, NULL) < 0) {
        perror("\n[ERROR]:pcapw_write");
        return;
    }

    pcapw_rec_hdr_t rec;
    rec.ts_sec = (uint32_t)now.tv_sec;
    rec.ts_usec = (uint32_t)now.tv_usec;
    rec.incl_len = (uint32_t)len;
    rec.orig_len = (uint32_t)len;   // ~ We never truncate, so what we stored is what was on the wire

    // ~ The record header first, then the frame itself right behind it
    if (fwrite(&rec, sizeof(rec), 1, self->file) != 1) {
        perror("\n[ERROR]:pcapw_write");
        return;
    }

    if (fwrite(frame, 1, len, self->file) != len) {
        perror("\n[ERROR]:pcapw_write");
        return;
    }

    self->frames_written += 1;
}

void pcapw_close(pcapw_t *self) {
    does_exist(self);

    // ~ There is nothing to close if a file was never opened
    if (self->file == NULL) {
        return;
    }

    OUTPUT_D_MSG("pcapw_close : Closing the pcap file...");

    if (fclose(self->file) != 0) {
        perror("\n[ERROR]:pcapw_close");
    }

    // ~ Back to "no file" so nobody tries to close this handle a second time
    self->file = NULL;

    OUTPUT_D_MSG("pcapw_close : Successfully closed the pcap file!");
}
