#pragma once

#include <iostream>
#include <vector>
#include <set>

#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_dl.h>

#include <ifaddrs.h>
 
// Get Destination Address
#define ETH_GDA(eth) \
    (struct ether_addr*)((struct eth_header*)eth->ether_dhost)

// Get Source Address
#define ETH_GSA(eth) \
    (struct ether_addr*)((struct eth_header*)eth->ether_shost)

// Set Destination Address
#define ETH_SDA(eth, addr) \
    *((struct ether_addr*)((struct eth_header*)eth->ether_dhost)) = *((struct ether_addr*)addr)

// Set Source Address
#define ETH_SSA(eth, addr) \
    *((struct ether_addr*)((struct eth_header*)eth->ether_shost)) = *((struct ether_addr*)addr)

void
swap_mac(struct ether_addr* mac1, struct ether_addr* mac2)
{
    struct ether_addr tmp;
    tmp = *mac1;
    *mac1 = *mac2;
    *mac2 = tmp;
    return;
}

void
printmac(const char* prefix, struct ether_addr* mac, const char* suffix)
{
    //struct ether_addr { 
    //    u_char octet[ETHER_ADDR_LEN];
    //} __packed;

    printf("%s"  , prefix);
    printf("%02x:", mac->octet[0]);
    printf("%02x:" , mac->octet[1]);
    printf("%02x:" , mac->octet[2]);
    printf("%02x:" , mac->octet[3]);
    printf("%02x:" , mac->octet[4]);
    printf("%02x " , mac->octet[5]);
    printf("%s"  , suffix);
    return;
}

bool is_exist_if(std::vector<std::string>& v, std::string& s)
{
    std::vector<std::string>::iterator it;
    bool retval = false;
    for (it = v.begin(); it != v.end(); it++) {
        if (*it == s) {
            retval = true;
        }
    }
    return retval;
}

std::vector<std::string>
get_ifname_list()
{
    //getmac
    struct ifaddrs *ifs;
    struct ifaddrs *ifp;
    //struct sockaddr_dl* dl;
    std::set<std::string> s;
    std::vector<std::string> v;

    if (getifaddrs(&ifs) != 0) {
        PERROR("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifp=ifs; ifp; ifp=ifp->ifa_next) {
        int ifp_family = ifp->ifa_addr->sa_family;

        if (ifp->ifa_addr == NULL) {
            continue;
        } else if (ifp_family != AF_LINK) {
            continue;
        }
        s.insert(std::string(ifp->ifa_name));

    }
    freeifaddrs(ifs);
    std::set<std::string>::iterator it;
    for (it = s.begin(); it != s.end(); it++) {
        v.push_back(*it);
    }
    return v;
}
