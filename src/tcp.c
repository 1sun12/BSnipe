
#include "tcp.h"
#include <arpa/inet.h>

tcp_t *tcp_create(void) {
    OUTPUT_D_MSG("tcp_create : Attempting to create a TCP parser object...");

    // ~ Create a new TCP Header parser
    tcp_t *new = NULL;
    
    // ~ Allocate memory
    if ((new = (tcp_t *)calloc(1, sizeof(tcp_t))) == NULL) {
        perror("\n[ERROR]:tcp_create");
        return NULL;
    }

    // ~ Initialize TCP Header with default value
    new->hdr = NULL;

    // ~ Wire up function pointers
    new->set_buffer = tcp_set_buffer;
    new->parse_src = tcp_parse_src;
    new->parse_dst = tcp_parse_dst;
    new->destroy = tcp_destroy;

    // ~ Return newly created object
    OUTPUT_D_MSG("tcp_create : Successfully created a TCP parser object!");
    return new;
}

void tcp_destroy(tcp_t **self_ptr) {
    does_exist(self_ptr);
    does_exist(*self_ptr);

    tcp_t *self = *self_ptr;

    OUTPUT_D_MSG("tcp_destroy : TCP parser being destroyed...");

    // ~ Deallocate this entire memory block
    free(self);
    *self_ptr = NULL;

    OUTPUT_D_MSG("tcp_destroy : TCP parser destroyed successfully!");
}

void tcp_set_buffer(tcp_t *self, void *buffer, uint8_t ip_hdr_len) {
    does_exist(self);
    does_exist(buffer);
    OUTPUT_D_MSG("tcp_set_buffer : Extracting TCP Header struct from the buffer...");

    // ~ Located at byte [ETH_HLEN + ip_hdr_len] is where the TCP Header begins
    self->hdr = (struct tcphdr*)((uint8_t*)buffer + ETH_HLEN + ip_hdr_len);

    OUTPUT_D_MSG("tcp_set_buffer : Successfully extracted the TCP Header struct from the buffer!");
}

void tcp_parse_src(tcp_t *self) {
    does_exist(self);
    does_exist(self->hdr);
    OUTPUT_D_MSG("tcp_parse_src : Attempting to parse the source port from the TCP Header...");

    // ~ Convert from network byte order and store as string
    uint16_t port = ntohs(self->hdr->source);
    sprintf(self->src_port, "%u", port);

    OUTPUT_D_MSG("tcp_parse_src : Successfully parsed the source port from the TCP Header!");
}

void tcp_parse_dst(tcp_t *self) {
    does_exist(self);
    does_exist(self->hdr);
    OUTPUT_D_MSG("tcp_parse_dst : Attempting to parse the destination port from the TCP Header...");

    // ~ Convert from network byte order and store as string
    uint16_t port = ntohs(self->hdr->dest);
    sprintf(self->dst_port, "%u", port);

    OUTPUT_D_MSG("tcp_parse_dst : Successfully parsed the destination port from the TCP Header!");
}