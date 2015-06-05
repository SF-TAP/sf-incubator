
#ifndef IPHDR_HPP
#define IPHDR_HPP

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "ether.hpp"
#include "common.hpp"
#include "netmap.hpp"

#define SELECTOR_HASH_SIZE 0xFFFF
#define hash32to16(h) ((h>>16) & (h&0x0000ffff))
#define NEXTHDR(ptr, count) (((uint8_t*)ptr)+count)

struct ip_hdr {
    uint8_t  hl:4;
    uint8_t  version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed, aligned(4)));


struct selector_info {
    uint32_t port;
};

struct selector_info* selector_info4;
struct selector_info* selector_info6;

void
selector_init(size_t hash_size)
{
    size_t memsize = sizeof(struct selector_info*) * SELECTOR_HASH_SIZE;

    selector_info4 =
        (struct selector_info*)malloc(memsize);
    memset(selector_info4, 0, memsize);

    selector_info6 =
        (struct selector_info*)malloc(memsize);
    memset(selector_info6, 0, memsize);

    return;
}

inline uint32_t
get_ip4_transport_key(struct ip_hdr* iphdr)
{
    uint32_t hash;
    uint32_t retval = 0;

    uint16_t offset = iphdr->frag_off & htons(IP_OFFMASK);

    if (offset == 0) {
        if ((iphdr->frag_off&htons(IP_MF)) == 0) {
            // offset off, MF off
            switch(iphdr->protocol)
            {
                case IPPROTO_TCP:
                {
                    struct tcphdr* tcphdr =
                        (struct tcphdr*)((char*)iphdr+(iphdr->hl<<2));
                    retval = tcphdr->th_sport ^ tcphdr->th_dport;
                    goto SUCCESS_V4;
                }

                case IPPROTO_UDP:
                {
                    struct udphdr* udphdr =
                        (struct udphdr*)((char*)iphdr+(iphdr->hl<<2));
                    retval = udphdr->uh_dport ^ udphdr->uh_sport;
                    goto SUCCESS_V4;
                }

                case IPPROTO_ICMP:
                {
                    goto NONSUPPORT_V4;
                }

                default:
                {
                    goto NONSUPPORT_V4;
                }
            }
        } else {
            // offset off, MF on 
            switch (iphdr->protocol)
            {
                case IPPROTO_TCP:
                {
                    struct tcphdr* tcphdr =
                        (struct tcphdr*)((char*)iphdr+(iphdr->hl<<2));
                    retval = tcphdr->th_dport ^ tcphdr->th_sport;
                    hash = (iphdr->id)^
                           (iphdr->saddr)^
                           (iphdr->daddr);
                    selector_info4[hash32to16(hash)].port = retval;
                    goto SUCCESS_V4;
                }

                case IPPROTO_UDP:
                {
                    struct udphdr* udphdr =
                        (struct udphdr*)((char*)iphdr+(iphdr->hl<<2));
                    retval = udphdr->uh_dport ^ udphdr->uh_sport;
                    hash = (iphdr->id)^
                           (iphdr->saddr)^
                           (iphdr->daddr);
                    selector_info4[hash32to16(hash)].port = retval;
                    goto SUCCESS_V4;
                }

                case IPPROTO_ICMP:
                {
                    goto NONSUPPORT_V4;
                }

                default:
                {
                    goto NONSUPPORT_V4;
                }
            }
        }
    } else {
        if ((iphdr->frag_off&htons(IP_MF)) == 0) {
            // offset on, MF off
            hash = (iphdr->id)^
                   (iphdr->saddr)^
                   (iphdr->daddr);
            retval = selector_info4[hash32to16(hash)].port;
            selector_info4[hash32to16(hash)].port = 0;
            goto SUCCESS_V4;
        } else {
            // offset on, MF on
            hash = (iphdr->id)^
                   (iphdr->saddr)^
                   (iphdr->daddr);
            retval = selector_info4[hash32to16(hash)].port;
            goto SUCCESS_V4;
        }
    }

    SUCCESS_V4:
    return retval;

    NONSUPPORT_V4:
    return 0;
}

inline uint32_t
get_ip6_transport_key(struct ip6_hdr* ip6hdr)
{
    //ref: rfc2292.html
    uint32_t retval = 0;
    uint32_t hash;
    switch (ip6hdr->ip6_nxt)
    {
        case IPPROTO_TCP:
        {
            struct tcphdr* tcphdr
                = (struct tcphdr*)((char*)ip6hdr+(sizeof(struct ip6_hdr)));
            retval = tcphdr->th_dport ^ tcphdr->th_sport;
            goto SUCCESS_V6;
        }

        case IPPROTO_UDP:
        {
            struct udphdr* udphdr
                = (struct udphdr*)((char*)ip6hdr+(sizeof(struct ip6_hdr)));
            retval = udphdr->uh_dport ^ udphdr->uh_sport;
            goto SUCCESS_V6;
        }

         /*
          * IPv6 fragment option header detail
          * 0                16               31
          * +--------+-------+-----------+--+-+
          * | nxthdr | rsrvd | f_offset  |rs|m|
          * +--------+-------+-----------+--+-+
          * |        32bit Identification     |
          * +----------------+----------------+
          * nexthdr     :  8bit of next header protorol
          * reserved    :  8bit of xxx
          * frag_offset : 13bit of fragment offset in 8-octet units
          * rs          :  2bit of reserved flag bit
          * m           :  1bit of fragment indication 1->more, 0->last
          */
        case IPPROTO_FRAGMENT:
        /*
        {
            struct v6opt_f_hdr {
                uint8_t next;
                uint8_t reserve;
                uint16_t offset:13;
                uint16_t reserve_flag:2;
                uint16_t m_flag:1;
                uint32_t id;
            } __attribute__((packed, aligned(4)));

            struct v6opt_f_hdr* fhdr;
                = (struct v6opt_f_hdr*)NEXTHDR(ip6hdr, sizeof(struct ip6_hdr));

            switch (fhdr->next); 
            {
                case IPPROTO_TCP:
                {
                    if (frag_offset == 0) {
                        struct tcphdr* tcphdr
                            = (struct tcphdr*)NEXTHDR(fhdr, sizeof(struct v6opt_f_hdr));
                        retval = tcphdr->th_dport ^ tcphdr->th_sport;
                        hash = xor6(ip6hdr->ip6_src) ^
                               xor6(ip6hdr->ip6_dst) ^
                               fhdr->id;
                        selector_info6[hash32to16(hash)].port = retval;
                        goto SUCCESS_V6;
                    } else if () {
                    }
                    goto SUCCESS_V6;
                }
                case IPPROTO_UDP:
                {
                    goto NONSUPPORT_V6;
                }
                default:
                {
                    goto NONSUPPORT_V6;
                }
            }
            goto NONSUPPORT_V6;
        }
        */

        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_ESP:
        case IPPROTO_AH:
        case IPPROTO_NONE:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ICMPV6:
        {
            goto NONSUPPORT_V6;
        }

        default:
        {
            goto NONSUPPORT_V6;
        }
    }

    SUCCESS_V6:
    return retval;

    NONSUPPORT_V6:
    return 0;
}

inline uint32_t
next_ip4(struct ip_hdr* iphdr, int flag)
{
    if (flag == 0) {
        return iphdr->saddr ^ iphdr->daddr;
    } else if (flag == 1) {
        return get_ip4_transport_key(iphdr);
    } else {
        return 0;
    }
    return 0;
}

#define xor6(inaddr6) inaddr6.__u6_addr.__u6_addr32[0] ^ \
                      inaddr6.__u6_addr.__u6_addr32[1] ^ \
                      inaddr6.__u6_addr.__u6_addr32[2] ^ \
                      inaddr6.__u6_addr.__u6_addr32[3]
inline uint32_t
next_ip6(struct ip6_hdr* ip6hdr, int flag)
{
    if (flag == 0) {
        return (xor6(ip6hdr->ip6_src)) ^ (xor6(ip6hdr->ip6_dst));
    } else if (flag == 1) {
        return get_ip6_transport_key(ip6hdr);
    } else {
        return 0;
    }
    return 0;
}

inline uint32_t
next_vlan(uint8_t* hdr, int flag)
{
    uint16_t tag_id = htons(hdr[0]);
    uint16_t next_type = htons(hdr[1]);
    uint8_t* next_hdr = NEXTHDR(hdr, 4);
    uint32_t selection;
    printf("vlanID: %d\n", tag_id);
    switch(next_type)
    {
        case ETHERTYPE_IP:
        {
            selection = next_ip4((struct ip_hdr*)next_hdr, flag);
            break;
        }

        case ETHERTYPE_IPV6:
        {
            selection = next_ip6((struct ip6_hdr*)next_hdr, flag);
            break;
        }

        default:
        {
            return 0;
            break;
        }
    }
    return selection;
}

// -1    : fail
// other : return interface number
// flag : 0 -> L3 base
//        1 -> L4 base
inline int
interface_selector(struct netmap_ring* ring,
        std::vector<struct tap_info>& v_tap_info, int flag)
{

    uint32_t selection = -1;
    if (v_tap_info.size() == 0) return selection;

    struct netmap_slot* rx_slot = 
         ((netmap_slot*)&ring->slot[ring->cur]);

    struct ether_header* hdrptr = 
        (struct ether_header*)NETMAP_BUF(ring, rx_slot->buf_idx);

    //size_t ethlen = rx_slot->len;

    //printf("%x\n", ntohs(hdrptr->ether_type));
    pktdump((uint8_t*)hdrptr, 64);


    switch(ntohs(hdrptr->ether_type))
    {
        case ETHERTYPE_IP:
        {
            selection = 
            next_ip4((struct ip_hdr*)NEXTHDR(hdrptr,
                        sizeof(struct ether_header)), flag);
            break;
        }

        case ETHERTYPE_IPV6:
        {
            selection = 
            next_ip6((struct ip6_hdr*)NEXTHDR(hdrptr,
                        sizeof(struct ether_header)), flag);
            break;
        }

        case ETHERTYPE_VLAN: //0x8100
        {
            printf("hoge\n");
            selection = 
            next_vlan(NEXTHDR(hdrptr, sizeof(struct ether_header)), flag);
            break;
        }

        default:
        {
            selection = 0;
            break;
        }

    }

    //printf("selection    :0x%x\n", selection);
    selection = selection % v_tap_info.size();
    //printf("selection_mod:0x%x\n", selection);

    return selection;
}


#endif
