#ifndef IP_H
#define IP_H

/**
 * @brief User headers
 */
#include "debug.h"

/**
 * @brief General headers
 */
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief Network headers
 * - netinet/ip.h           |   Contains structure for IP headers (struct iphdr)
 * - netinet/if_ether.h     |   Ethernet header length (ETH_HLEN), the IP header sits right behind it
 */
#include <netinet/ip.h>
#include <netinet/if_ether.h>

typedef struct ip_t ip_t;
struct ip_t {
    /**
     * @brief The unique integer variables that make up an IP header (minimum 20 bytes):
     * - uint8_t tos;        |   Type of Service - priority hints for routers (QoS). "Treat this VoIP packet with low latency."
     * - uint16_t tot_len;   |   Total Length - entire packet size in bytes. Receiver knows where this packet ends.
     * - uint16_t id;        |   Identification - unique ID so fragments can be reassembled. Same ID = same original packet.
     * - uint16_t frag_off;  |   Fragment Offset - where this fragment belongs in the original packet (in 8-byte units).
     * - uint8_t ttl;        |   Time To Live - max hops before packet dies. Prevents infinite routing loops.
     * - uint8_t protocol;   |   Protocol - what's inside the payload (6=TCP, 17=UDP, 1=ICMP). NOT HTTP/SSH!!!!, those are Layer 7 in the OSI model.
     * - uint16_t check;     |   Header Checksum - integrity check for the header. Detects corruption in transit.
     * - uint32_t saddr;     |   Source Address - 32-bit IPv4 address of sender.
     * - uint32_t daddr;     |   Destination Address - 32-bit IPv4 address of recipient.
     */
    struct iphdr *hdr;
    char src_ip[16];
    char dst_ip[16];

    void (*set_buffer)(ip_t *self, void *buffer);
    void (*parse_src)(ip_t *self);
    void (*parse_dst)(ip_t *self);
    void (*destroy)(ip_t **self_ptr);
};

ip_t *ip_create(void);

void ip_destroy(ip_t **self_ptr);

void ip_set_buffer(ip_t *self, void *buffer);

void ip_parse_src(ip_t *self);

void ip_parse_dst(ip_t *self);

#endif