#include <iostream>

#include <net/ethernet.h>

#include "../common.hpp"
#include "../netmap.hpp"

#include "../ether.hpp"

extern bool debug;

int
main(int argc, char** argv)
{

    if (argc != 2) {
        printf("%s [interface name]", argv[0]);
        exit(EXIT_FAILURE);
    }

    debug = true;

    int tx_fd;
    int rx_fd;

    struct ether_header* eth;
    size_t ethlen;
    netmap nm;

    netmap_ring* txring = NULL;
    netmap_ring* rxring = NULL;

    nm.open_if(argv[1]);
    nm.set_promisc();
    int ringid = 0;

    tx_fd = nm.create_nmring_hard_tx(&txring, ringid);
    rx_fd = nm.create_nmring_hard_rx(&rxring, ringid);

    printf("tx_pointer:%p\n", txring);
    printf("rx_pointer:%p\n", rxring);
    printf("tx_fd:%d\n", tx_fd);
    printf("rx_fd:%d\n", rx_fd);

    for (;;) {

        nm.rxsync(rx_fd, ringid);

        while (rxring->avail > 0) {

            if (txring->avail == 0) break;

            eth = nm.get_eth(rxring);
            ethlen = nm.get_ethlen(rxring);

            /*
            printmac("dst_mac:", ETH_GDA(eth), "\n");
            printmac("src_mac:", ETH_GSA(eth), "\n");
            */

            ETH_SDA(eth, ETH_GSA(eth));
            ETH_SSA(eth, nm.get_mac());

            printf("frmae length %lu\n", ethlen);
            pktdump((uint8_t*)eth, ethlen);

            struct ether_header* eth_tx = nm.get_eth(txring);

            memcpy(eth_tx, eth, ethlen);
            nm.set_ethlen(txring, ethlen);

            txring->avail--;
            nm.next(txring);

            rxring->avail--;
            nm.next(rxring);
        }

        nm.txsync(tx_fd, ringid);

    }
    return EXIT_SUCCESS;
}
