#ifndef TCP_H
#define TCP_H

#include "debug.h"

#include <stdio.h>
#include <stdlib.h>

#include <netinet/tcp.h>
#include <netinet/if_ether.h>

typedef struct tcp_t tcp_t;
struct tcp_t {
    struct tcphdr *hdr;
    char src_port[6];
    char dst_port[6];

    void (*set_buffer)(tcp_t *self, void *buffer, uint8_t ip_hdr_len);
    void (*parse_src)(tcp_t *self);
    void (*parse_dst)(tcp_t *self);
    void (*destroy)(tcp_t **self_ptr);
};

tcp_t *tcp_create(void);

void tcp_destroy(tcp_t **self_ptr);

void tcp_set_buffer(tcp_t *self, void *buffer, uint8_t ip_hdr_len);

void tcp_parse_src(tcp_t *self);

void tcp_parse_dst(tcp_t *self);

#endif