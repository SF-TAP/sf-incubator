#pragma once

#include <iostream>
#include <vector>
#include <set>
#include <regex.h>

#include <sys/socket.h>
#include <net/ethernet.h>
#ifndef __linux__
#include <net/if_dl.h>
#endif

#include <ifaddrs.h>

#define ETHER_ADDR_REGEX "(^[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]$)"
 
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

bool
is_ether_addr(char *addr)
{
    regex_t regex;

    if (regcomp(&regex, ETHER_ADDR_REGEX, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
        return false;
    }

    if (regexec(&regex, addr, 0, NULL, 0) == 0) {
        regfree(&regex);
        return true;
    }
    regfree(&regex);
    return false;
}

void
printmac(const char* prefix, struct ether_addr* mac, const char* suffix)
{
#ifndef __linux__
    /*
    // freebsd
    struct ether_addr { 
        u_char octet[ETHER_ADDR_LEN];
    } __packed;
    */

    printf("%s"    , prefix);
    printf("%02x:" , mac->octet[0]);
    printf("%02x:" , mac->octet[1]);
    printf("%02x:" , mac->octet[2]);
    printf("%02x:" , mac->octet[3]);
    printf("%02x:" , mac->octet[4]);
    printf("%02x " , mac->octet[5]);
    printf("%s"  , suffix);
#else
    /*
    // linux
    struct ether_addr {
       u_int8_t ether_addr_octet[ETH_ALEN];
    } __attribute__ ((__packed__));
    */
    printf("%s"    , prefix);
    printf("%02x:" , mac->ether_addr_octet[0]);
    printf("%02x:" , mac->ether_addr_octet[1]);
    printf("%02x:" , mac->ether_addr_octet[2]);
    printf("%02x:" , mac->ether_addr_octet[3]);
    printf("%02x:" , mac->ether_addr_octet[4]);
    printf("%02x " , mac->ether_addr_octet[5]);
    printf("%s"  , suffix);
#endif

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
    std::vector<std::string> v;

#ifndef __linux__
    std::set<std::string> s;
    struct ifaddrs *ifs;
    struct ifaddrs *ifp;

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

#else

    std::set<std::string> s;
    struct ifaddrs *ifs;
    struct ifaddrs *ifp;

    if (getifaddrs(&ifs) != 0) {
        PERROR("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifp=ifs; ifp; ifp=ifp->ifa_next) {
        if (ifp->ifa_addr == NULL) {
            continue;
        }
        s.insert(std::string(ifp->ifa_name));
    }
    freeifaddrs(ifs);

    std::set<std::string>::iterator it;
    for (it = s.begin(); it != s.end(); it++) {
        //std::cout << *it << std::endl;
        v.push_back(*it);
    }

#endif

    return v;
}
