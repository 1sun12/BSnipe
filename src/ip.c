
#include "ip.h"

ip_t *ip_create(void) {
    OUTPUT_D_MSG("ip_create : Attempting to create an IP parser object...");

    // ~ Create a new IP Header parser
    ip_t *new = NULL;
    
    // ~ Allocate memory
    if ((new = (ip_t *)calloc(1, sizeof(ip_t))) == NULL) {
        perror("\n[ERROR]:ip_create");
        return NULL;
    }

    // ~ Initialize IP Header with default value, no need to malloc because it will point at existing memory
    new->hdr = NULL;

    // ~ Wire up function pointers
    new->set_buffer = ip_set_buffer;
    new->parse_src = ip_parse_src;
    new->parse_dst = ip_parse_dst;
    new->destroy = ip_destroy;

    // ~ Return newly created object
    OUTPUT_D_MSG("ip_create : Successfully created an IP parser object!");
    return new;
}

void ip_destroy(ip_t **self_ptr) {
    does_exist(self_ptr);
    does_exist(*self_ptr);

    ip_t *self = *self_ptr;

    OUTPUT_D_MSG("ip_destroy : IP parser being destroyed...");

    // ~ Deallocate this entire memory block
    free(self);
    *self_ptr = NULL;

    OUTPUT_D_MSG("ip_destroy : IP parser destroyed successfully!");
}

void ip_set_buffer(ip_t *self, void *buffer) {
    does_exist(self);
    does_exist(buffer);
    OUTPUT_D_MSG("ip_set_buffer : Extracting IP Header struct from the buffer...");

    // ~ Located at byte [ETH_HLEN] (14) is where the IP Header begins, so we acquire the address (&) of that byte and hard-cast it to a iphdr struct
    self->hdr = (struct iphdr*)((uint8_t*)buffer + ETH_HLEN);

    OUTPUT_D_MSG("ip_set_buffer : Successfully extracted the IP Header struct from the buffer!");
}


void ip_parse_src(ip_t *self) {
    does_exist(self);
    does_exist(self->hdr);
    OUTPUT_D_MSG("ip_parse_src : Attempting to parse the source IP from the IP Header...");

    // ~ Copy the source IP into a local-scope variable for re-arranging
    uint32_t local_source_ip = self->hdr->saddr;

    // ~ Create a 1-byte unsigned integer representing each of the 4-bytes that make up the IP Address
    uint8_t *byte_shifter = (uint8_t *)&local_source_ip;

    uint8_t octet0 = byte_shifter[0];   // ~ [0] - same byte as local_source_ip starts at
    uint8_t octet1 = byte_shifter[1];   // ~ [1] - shift over +1 in memory space
    uint8_t octet2 = byte_shifter[2];   // ~ [2] - shift over +2 in memory space
    uint8_t octet3 = byte_shifter[3];   // ~ [3] - shift over +3 in memory space

    // ~ Print each byte seperated by "." ; an IPv4 address!
    sprintf(self->src_ip, "%u.%u.%u.%u", octet0, octet1, octet2, octet3);

    OUTPUT_D_MSG("ip_parse_src : Successfully parsed the source IP from the IP Header!");
}


void ip_parse_dst(ip_t *self) {
    does_exist(self);
    does_exist(self->hdr);
    OUTPUT_D_MSG("ip_parse_dst : Attempting to parse the destination IP from the IP Header...");

    // ~ Copy the destination IP into a local-scope variable for re-arranging
    uint32_t local_destination_ip = self->hdr->daddr;

    // ~ Create a 1-byte unsigned integer representing each of the 4-bytes that make up the IP Address
    uint8_t *byte_shifter = (uint8_t *)&local_destination_ip;

    uint8_t octet0 = byte_shifter[0];   // ~ [0] - same byte as local_source_ip starts at
    uint8_t octet1 = byte_shifter[1];   // ~ [1] - shift over +1 in memory space
    uint8_t octet2 = byte_shifter[2];   // ~ [2] - shift over +2 in memory space
    uint8_t octet3 = byte_shifter[3];   // ~ [3] - shift over +3 in memory space

    // ~ Print each byte seperated by "." ; an IPv4 address!
    sprintf(self->dst_ip, "%u.%u.%u.%u", octet0, octet1, octet2, octet3);

    OUTPUT_D_MSG("ip_parse_dst : Successfully parsed the destination IP from the IP Header!");
}
