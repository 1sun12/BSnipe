#include "eth.h"

eth_t *eth_create(void) {
    OUTPUT_D_MSG("eth_create : Creating a new ethernet parser...");

    // ~ Create a new ethernet parser
    eth_t *new = NULL;

    // ~ Allocate however many bytes are needed and zero + error check
    new = (eth_t *)calloc(1, sizeof(eth_t));
    if (new == NULL) {
        perror("\n[ERROR]:eth_create");
        return NULL;
    }

    // ~ Initialize ethernet header with default value, no need to malloc because this will point to existing memory already (our buffer)
    new->hdr = NULL;

    // ~ Wire up function pointers
    new->set_buffer = eth_set_buffer;
    new->parse = eth_parse;
    new->destroy = eth_destroy;

    // ~ Return the newly created parser
    OUTPUT_D_MSG("eth_create : Successfully created ethernet parser!");
    return new;
}

void eth_destroy(eth_t **self_ptr) {
    does_exist(self_ptr);
    does_exist(*self_ptr);

    eth_t *self = *self_ptr;

    OUTPUT_D_MSG("eth_destroy : Ethernet parser being destroyed...");

    // ~ Deallocate this entire memory block
    free(self);
    *self_ptr = NULL;

    OUTPUT_D_MSG("eth_destroy : Ethernet parser destroyed successfully!");
}

void eth_set_buffer(eth_t *self, void *buffer) {
    does_exist(self);
    does_exist(buffer);
    OUTPUT_D_MSG("eth_set_buffer : Casting buffer to ethernet header structure...");

    // ~ Cast buffer to ethernet header structure
    self->hdr = (struct ethhdr *)buffer;

    OUTPUT_D_MSG("eth_set_buffer : Successfully casted buffer space to an ethernet header structure!");
}

void eth_parse(eth_t *self) {
    does_exist(self);
    does_exist(self->hdr);
    OUTPUT_D_MSG("eth_parse : Parsing Ethernet Header and extracting MAC addresses + next layer...");

    // ~ Convert source MAC address to a string, from the ethernet header
    sprintf(self->src_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
        self->hdr->h_source[0],
        self->hdr->h_source[1],
        self->hdr->h_source[2],
        self->hdr->h_source[3],
        self->hdr->h_source[4],
        self->hdr->h_source[5]);

    // ~ Convert destination MAC address to a string, from the ethernet header
    sprintf(self->dst_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
        self->hdr->h_dest[0],
        self->hdr->h_dest[1],
        self->hdr->h_dest[2],
        self->hdr->h_dest[3],
        self->hdr->h_dest[4],
        self->hdr->h_dest[5]);

    // ~ ntohs has already flipped this into host byte order, hence the name
    uint16_t ethertype_host = ntohs(self->hdr->h_proto);

    sprintf(self->ethertype, "0x%04X", ethertype_host);

    OUTPUT_D_MSG("eth_parse : Successfully parsed the Ethernet Header!");
}
