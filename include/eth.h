#ifndef ETH_H
#define ETH_H

#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/if_ether.h>
#include <arpa/inet.h>

typedef struct eth_t eth_t;
struct eth_t {
    struct ethhdr *hdr;
    char src_mac[18];
    char dst_mac[18];
    char ethertype[7];

    void (*set_buffer)(eth_t *self, void *buffer);
    void (*parse)(eth_t *self);
    void (*destroy)(eth_t **self_ptr);
};

eth_t *eth_create(void);

void eth_destroy(eth_t **self_ptr);

void eth_set_buffer(eth_t *self, void *buffer);

void eth_parse(eth_t *self);

#endif