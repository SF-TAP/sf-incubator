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


    struct ether_header* eth;
    size_t ethlen;
    netmap nm;

    netmap_ring* txring = NULL;
    netmap_ring* rxring = NULL;

    nm.open_if(argv[1]);
    nm.set_promisc();
    for (int i = 0; i<nm.get_rx_qnum(); i++) {
        nm.create_nmring_hard_rx(NULL, i);
    }

    for (int i = 0; i<nm.get_tx_qnum(); i++) {
        nm.create_nmring_hard_tx(NULL, i);
    }

    for (;;) {

        nm.rxsync_pollall();

        for (int i = 0; i<nm.get_rx_qnum(); i++) {
            rxring = nm.get_rx_ring_info_ring(i);
            txring = nm.get_tx_ring_info_ring(i%nm.get_tx_qnum());
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
        }

        nm.txsync_pollall();

    }
    return EXIT_SUCCESS;
}
