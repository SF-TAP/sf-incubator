#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int
main(int argc, char** argv)
{
    if (argc != 6) {
        printf("%s [src_ip] [dst_ip] [src_port] [dst_port] [div]\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct sockaddr_in sain_src;
    memset(&sain_src, 0, sizeof(struct sockaddr_in));
    struct sockaddr_in sain_dst;
    memset(&sain_dst, 0, sizeof(struct sockaddr_in));

    inet_pton(AF_INET, argv[1], &sain_src);
    inet_pton(AF_INET, argv[2], &sain_dst);

    uint32_t srcip = (uint32_t)sain_src.sin_addr.s_addr;
    uint32_t dstip = (uint32_t)sain_dst.sin_addr.s_addr;
    uint16_t srcport = htons(atoi(argv[3]));
    uint16_t dstport = htons(atoi(argv[4]));
    int div = atoi(argv[5]);

    uint32_t sum = srcip ^ dstip;
    if (srcport <= dstport) {
        sum = srcport<<16 | dstport;
    } else {
        sum = dstport<<16 | srcport;
    }

    printf("%d\n", sum%div);

    return 0;
}
