#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
// IPv4 header
struct IpHdr final {
    uint8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */

    uint8_t ip_tos;       /* type of service */
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    Ip ip_src; /* source and dest address */
    Ip ip_dst;

    uint8_t iphl() {return ip_hl;}
    uint8_t ipv() {return ip_v;}
    Ip sip() {return ntohl(ip_src);}
    Ip dip() {return ntohl(ip_dst);}
};

typedef IpHdr *PIpHdr;
#pragma pack(pop)