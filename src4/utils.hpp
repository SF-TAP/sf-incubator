#ifndef __UTILS_HPP__
#define __UTILS_HPP__

#include <stdio.h>
#include <string.h>
#include <string>
#include <time.h>
#include <arpa/inet.h>

bool debug = true;

#ifdef DEBUG
#define MESG(format, ...) do {                             \
    if (debug) {                                           \
        fprintf(stderr, "%s:%s(%d): " format "\n",         \
        __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);  \
    }                                                      \
} while (false)
#else
#define MESG(format, ...) do {} while (false)
#endif //DEBUG

#ifdef DEBUG
#define PERROR(func) do {                    \
    if (debug) {                             \
    char s[BUFSIZ];                          \
    memset(s, 0, BUFSIZ);                    \
    snprintf(s, BUFSIZ, "%s:%s(%d): %s",     \
    __FILE__, __FUNCTION__, __LINE__, func); \
    perror(s);                               \
    }                                        \
} while (false)
#else
#define PERROR(func) do {} while (false)
#endif //DEBUG

bool is_ipv4_address(const std::string &addr)
{
    struct sockaddr_in sin;
    if (inet_pton(AF_INET, addr.c_str(), &sin.sin_addr) > 0) {
        return true;
    } else {
        return false;
    }
}

/*
void memdump(void* buffer, int length)
{
    uint32_t* addr32 = (uint32_t*)buffer;
    int i;
    int j;
    int k;
    int lines = length/16 + (length%16?1:0);
    if (lines > 1) {
        for (i=0; i<lines; i++) {
            printf("%p : %08x %08x %08x %08x\n",
                    addr32,
                    htonl(*(addr32)),
                    htonl(*(addr32+1)),
                    htonl(*(addr32+2)),
                    htonl(*(addr32+3))
                  );
            addr32 += 4;
        }
    } else {
    }

    j = length%16;
    if (j == 0) return;
    k = 0;
    uint8_t*  addr8 = (uint8_t*)addr32;
    printf("%p : ", addr8);
    for (i=0; i<16; i++) {
        if (k%4 == 0 && i != 0) printf(" ");
        if (j > i) {
            printf("%02x", *addr8);
            addr8++;
        } else {
            printf("XX");
        }
        k++;
    }
    printf("\n");
    return;
}
*/


#endif //__UTILS_HPP__

