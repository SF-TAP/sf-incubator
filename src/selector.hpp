
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
}  __packed __aligned(4);

struct selector_info {
    uint32_t port;
};

struct selector_info* selector_info;
size_t selector_hash_size;

void
selector_init(size_t hash_size)
{
    size_t memsize = sizeof(struct selector_info*) * hash_size;
    selector_hash_size = hash_size;
    selector_info =
        (struct selector_info*)malloc(memsize);
    memset(selector_info, 0, memsize);
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
                    if (tcphdr->th_sport <= tcphdr->th_dport) {
                        retval = tcphdr->th_sport<<16 | tcphdr->th_dport;
                    } else {
                        retval = tcphdr->th_dport<<16 | tcphdr->th_sport;
                    }
                    goto SUCCESS;
                    break;
                }

                case IPPROTO_UDP:
                {
                    struct udphdr* udphdr =
                        (struct udphdr*)((char*)iphdr+(iphdr->hl<<2));
                    if (udphdr->uh_sport <= udphdr->uh_dport) {
                        retval = udphdr->uh_sport<<16 | udphdr->uh_dport;
                    } else {
                        retval = udphdr->uh_dport<<16 | udphdr->uh_sport;
                    }
                    goto SUCCESS;
                    break;
                }

                case IPPROTO_ICMP:
                {
                    goto NONSUPPORT;
                    break;
                }

                default:
                {
                    goto NONSUPPORT;
                    break;
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
                    if (tcphdr->th_sport <= tcphdr->th_dport) {
                        retval = tcphdr->th_sport<<16 | tcphdr->th_dport;
                    } else {
                        retval = tcphdr->th_dport<<16 | tcphdr->th_sport;
                    }
                    hash = (iphdr->id)^
                           (iphdr->saddr)^
                           (iphdr->daddr);
                    selector_info[hash/selector_hash_size].port = retval;
                    goto SUCCESS;
                }

                case IPPROTO_UDP:
                {
                    struct udphdr* udphdr =
                        (struct udphdr*)((char*)iphdr+(iphdr->hl<<2));
                    if (udphdr->uh_sport<<16 <= udphdr->uh_dport) {
                        retval = udphdr->uh_sport<<16 | udphdr->uh_dport;
                    } else {
                        retval = udphdr->uh_dport<<16 | udphdr->uh_sport;
                    }
                    hash = (iphdr->id)^
                           (iphdr->saddr)^
                           (iphdr->daddr);
                    selector_info[hash/selector_hash_size].port = retval;
                    goto SUCCESS;
                }

                case IPPROTO_ICMP:
                {
                    goto NONSUPPORT;
                }

                default:
                {
                    goto NONSUPPORT;
                }
            }
        }
    } else {
        if ((iphdr->frag_off&htons(IP_MF)) == 0) {
            // offset on, MF off
            hash = (iphdr->id)^
                   (iphdr->saddr)^
                   (iphdr->daddr);
            retval = selector_info[hash/selector_hash_size].port;
            selector_info[hash/selector_hash_size].port = 0;
            goto SUCCESS;
        } else {
            // offset on, MF on
            hash = (iphdr->id)^
                   (iphdr->saddr)^
                   (iphdr->daddr);
            retval = selector_info[hash/selector_hash_size].port;
            goto SUCCESS;
        }
    }

    SUCCESS:
    return retval;

    NONSUPPORT:
    return 0;
}

inline uint32_t
next_ip4(struct ip_hdr* iphdr, int flag)
{
    if (flag == 0) {
        return iphdr->saddr ^ iphdr->daddr;
    } else if (flag == 1) {
        /*
        uint16_t sport = tmp>>16;
        uint16_t dport = (uint16_t)tmp;
        */
        return get_ip4_transport_key(iphdr);
    } else {
        return 0;
    }
}

inline uint32_t
next_ip6(struct ip6_hdr* ip6hdr, int flag)
{
    return 0;
}

// -1    : fail
// other : return interface number
inline int
interface_selector(struct netmap_ring* ring,
        std::vector<struct tap_info>& v_tap_info, int flag)
{

    uint32_t selection = -1;
    if (v_tap_info.size() == 0) return selection;

    struct netmap_slot* rx_slot = 
         ((netmap_slot*)&ring->slot[ring->cur]);

    struct ether_header* eth = 
        (struct ether_header*)NETMAP_BUF(ring, rx_slot->buf_idx);

    //size_t ethlen = rx_slot->len;

    switch(ntohs(eth->ether_type))
    {
        case ETHERTYPE_IP:
        {
            selection = 
            next_ip4((struct ip_hdr*)NEXTHDR(eth,
                        sizeof(struct ether_header)), flag);
            break;
        }
        case ETHERTYPE_IPV6:
        {
            selection = 
            next_ip6((struct ip6_hdr*)NEXTHDR(eth,
                        sizeof(struct ether_header)), flag);
        }

        case ETHERTYPE_VLAN:
        {
            selection = 0;
        }

        default:
        {
            selection = 0;
        }

    }

    //printf("selection    :0x%x\n", selection);
    selection = selection % v_tap_info.size();
    //printf("selection_mod:0x%x\n", selection);

    return selection;
}


#endif
