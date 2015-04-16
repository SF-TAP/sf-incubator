
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <sys/param.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/netmap.h>
#include <net/netmap_user.h>

void
dump_netmap_request(struct nmreq* nmr)
{

#if NETMAP_API > 4
        /*
        struct nmreq {
            char        nr_name[IFNAMSIZ];
            uint32_t    nr_version;
            uint32_t    nr_offset;
            uint32_t    nr_memsize;
            uint32_t    nr_tx_slots;
            uint32_t    nr_rx_slots;
            uint16_t    nr_tx_rings;
            uint16_t    nr_rx_rings;
            uint16_t    nr_ringid;
            uint16_t    nr_cmd;
            uint16_t    nr_arg1;
            uint16_t    nr_arg2;
            uint32_t    spare2[3];
        };
        */
        printf("nr_name     : %s\n", nmr->nr_name);
        printf("nr_varsion  : %d\n", nmr->nr_version);
        printf("nr_offset   : %d\n", nmr->nr_offset);
        printf("nr_memsize  : %d\n", nmr->nr_memsize);
        printf("nr_tx_slots : %d\n", nmr->nr_tx_slots);
        printf("nr_rx_slots : %d\n", nmr->nr_rx_slots);
        printf("nr_tx_rings : %d\n", nmr->nr_tx_rings);
        printf("nr_rx_rings : %d\n", nmr->nr_rx_rings);
        printf("nr_ringid   : %d\n", nmr->nr_ringid);
        printf("nr_cmd      : %d\n", nmr->nr_cmd);
        printf("nr_arg1     : %d\n", nmr->nr_arg1);
        printf("nr_arg2     : %d\n", nmr->nr_arg2);
        printf("nr_arg3     : %x\n", nmr->nr_arg3);
        printf("nr_flags    : %x\n", nmr->nr_flags);
        printf("nr_spare2[0]: %x\n", nmr->spare2[0]);
#else
        /*
        struct nmreq {
            char        nr_name[IFNAMSIZ];
            uint32_t    nr_version;
            uint32_t    nr_offset;
            uint32_t    nr_memsize;
            uint32_t    nr_tx_slots;
            uint32_t    nr_rx_slots;
            uint16_t    nr_tx_rings;
            uint16_t    nr_rx_rings;
            uint16_t    nr_ringid;
            uint16_t    nr_cmd;
            uint16_t    nr_arg1;
            uint16_t    nr_arg2;
            uint32_t    spare2[3];
        };
        */
        printf("nr_name     : %s\n", nmr->nr_name);
        printf("nr_varsion  : %d\n", nmr->nr_version);
        printf("nr_offset   : %d\n", nmr->nr_offset);
        printf("nr_memsize  : %d\n", nmr->nr_memsize);
        printf("nr_tx_slots : %d\n", nmr->nr_tx_slots);
        printf("nr_rx_slots : %d\n", nmr->nr_rx_slots);
        printf("nr_tx_rings : %d\n", nmr->nr_tx_rings);
        printf("nr_rx_rings : %d\n", nmr->nr_rx_rings);
        printf("nr_ringid   : %d\n", nmr->nr_ringid);
        printf("nr_cmd      : %d\n", nmr->nr_cmd);
        printf("nr_arg1     : %d\n", nmr->nr_arg1);
        printf("nr_arg2     : %d\n", nmr->nr_arg2);
        printf("nr_spare2[0]: %x\n", nmr->spare2[0]);
        printf("nr_spare2[1]: %x\n", nmr->spare2[1]);
        printf("nr_spare2[2]: %x\n", nmr->spare2[2]);
#endif
    return;
}

int
main(int argc, char** argv)
{

    if (argc != 2) {
        printf("getinfo [interface_name]\n");
        return EXIT_FAILURE;
    }
        
    int fd;
    struct nmreq nmr;
    fd = open("/dev/netmap", O_RDWR);
    if (fd < 0) {
        perror ("open");
        return EXIT_FAILURE;
    }
    memset(&nmr, 0, sizeof(nmr));
    nmr.nr_version = NETMAP_API;
    strncpy(nmr.nr_name, argv[1], strlen(argv[1]));
    if (ioctl(fd, NIOCGINFO, &nmr) < 0) {
        perror("ioctl");
        return EXIT_FAILURE;
    }
    dump_netmap_request(&nmr);

    close(fd);
    return EXIT_SUCCESS;
}
