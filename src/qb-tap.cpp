
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#include <unistd.h>
#include <pthread.h>
#include <pthread_np.h>

#include <getopt.h>
#include <net/ethernet.h>

#include "common.hpp"
#include "netmap.hpp"
#include "ether.hpp"

extern bool debug;

bool bind_cpu(int cpu, int reverse);

void* th_left_to_right(void* param);
void* th_right_to_left(void* param);
void* th_tap(void* param);

void tap_processing(netmap* nm,
        int ringid, std::vector<netmap*>* v_nm_tap);
void fw_processing(netmap* nm_rx, netmap* nm_tx,
        int rx_ringid, int tx_ringid, std::vector<netmap*>* v_nm_tap);

inline void
frame_copy(struct netmap_ring* rxring, struct netmap_ring* txring);

void usage(char* prog_name);

struct thread_param {
    int rx_ringid;
    int tx_ringid;
    netmap* nm_rx;
    netmap* nm_tx;
    std::vector<netmap*>* nm_tap;
};

struct tap_info {
    int fd;
    int ringid;
    struct netmap_ring* ring;
    netmap* nm;
};

int
main(int argc, char** argv)
{
    debug = false;
    int opt;
    int option_index;
    std::string opt_l;
    std::string opt_r;
    std::string opt_t;

    std::vector<std::string> tap_list;
    std::vector<std::string> if_list = get_ifname_list();

    struct option long_options[] = {
        {"help",  no_argument, NULL, 'h'},
        {"left",  no_argument, NULL, 'l'},
        {"right", no_argument, NULL, 'r'},
        {"tap",   no_argument, NULL, 't'},
#ifdef DEBUG
        {"verbose", no_argument, NULL, 'v'},
#endif
        {0, 0, 0, 0},
    };

    while ((opt = getopt_long(argc, argv,
                "l:r:t:hv?", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
#ifdef DEBUG
        case 'v':
            debug = true;
            break;
#endif
        case 'l':
            opt_l = optarg;
            break;

        case 'r':
            opt_r = optarg;
            break;

        case 't':
            opt_t = optarg;
            break;

        case 'h':
        case '?':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;

        default:
            exit(EXIT_FAILURE);
        }
    }


    netmap* nm_l;
    if (opt_l.size() == 0) {
        nm_l = NULL;
    } else if (!is_exist_if(if_list, opt_l)) {
        MESG("-l is not exist interface.");
        exit(EXIT_FAILURE);
    } else {
        nm_l = new netmap();
        nm_l->open_if(opt_l);
        nm_l->set_promisc();
    }

    netmap* nm_r;
    if (opt_r.size() == 0) {
        nm_r = NULL;
    } else if (!is_exist_if(if_list, opt_r)) {
        MESG("-r is not exist interface.");
        exit(EXIT_FAILURE);
    } else {
        nm_r = new netmap();
        nm_r->open_if(opt_r);
        nm_r->set_promisc();
    }

    if (nm_l == NULL && nm_r == NULL) {
        usage(argv[0]);
        MESG("-l/-r have to assigned interface.");
        exit(EXIT_FAILURE);
    }

    if ((opt_l == opt_r) && (nm_l != NULL) && (nm_r != NULL)) {
        MESG("-l/-r is same interface.");
        exit(EXIT_FAILURE);
    }

    tap_list = split(opt_t, ",");
    if (opt_t.size() == 0) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    for (auto it : tap_list) {
        if (!is_exist_if(if_list, it)) {
            MESG("-t is included non exist interface.");
            exit(EXIT_FAILURE);
        }
    }

    if (is_exist_if(tap_list, opt_l)) {
        MESG("-t is included -l interface.");
        exit(EXIT_FAILURE);
    }

    if (is_exist_if(tap_list, opt_r)) {
        MESG("-t is included -r interface.");
        exit(EXIT_FAILURE);
    }

    std::vector<netmap*> v_nm_t;
    for (auto it : tap_list) {
        netmap* nm_tmp = new netmap();
        nm_tmp->open_if(it);
        for (int i=0; i<nm_tmp->get_tx_qnum(); i++) {
            nm_tmp->create_nmring_hard_tx(NULL, i);
        }
        v_nm_t.push_back(nm_tmp);
    }

    //nm_l.dump_nmr();
    //nm_r.dump_nmr();

    if (nm_l != NULL && nm_r != NULL) {

        // inline mode
        uint16_t rx_qnum;
        uint16_t tx_qnum;

        rx_qnum = nm_l->get_rx_qnum();
        tx_qnum = nm_r->get_tx_qnum();
        pthread_t* pth_lr = (pthread_t*)malloc(sizeof(pthread_t)*rx_qnum);
        if (pth_lr == NULL) {
            PERROR("malloc");
            exit(EXIT_FAILURE);
        }
        memset(pth_lr, 0, sizeof(pthread_t)*rx_qnum);
        if (debug) printf("l2r_th:%d\n", rx_qnum);

        for (int i = 0; i < rx_qnum; i++) {
            struct thread_param* param;
            param = (struct thread_param*)malloc(sizeof(struct thread_param));
            if (param == NULL) {
                PERROR("malloc");
                exit(EXIT_FAILURE);
            }
            memset(param, 0, sizeof(struct thread_param));
            param->rx_ringid = i;
            param->tx_ringid = i % tx_qnum;
            param->nm_rx = nm_l;
            param->nm_tx = nm_r;
            param->nm_tap = &v_nm_t;
            pthread_create(&pth_lr[i], NULL, th_left_to_right, param);
        }

        rx_qnum = nm_r->get_rx_qnum();
        tx_qnum = nm_l->get_tx_qnum();
        pthread_t* pth_rl = (pthread_t*)malloc(sizeof(pthread_t)*rx_qnum);
        if (pth_rl == NULL) {
            PERROR("malloc");
            exit(EXIT_FAILURE);
        }
        memset(pth_rl, 0, sizeof(pthread_t)*rx_qnum);
        if (debug) printf("r2l_th:%d\n", rx_qnum);

        for (int i = 0; i < rx_qnum; i++) {
            struct thread_param* param;
            param = (struct thread_param*)malloc(sizeof(struct thread_param));
            if (param == NULL) {
                PERROR("malloc");
                exit(EXIT_FAILURE);
            }
            memset(param, 0, sizeof(struct thread_param));
            param->rx_ringid = i;
            param->tx_ringid = i % tx_qnum;
            param->nm_rx = nm_r;
            param->nm_tx = nm_l;
            param->nm_tap = &v_nm_t;
            pthread_create(&pth_rl[i], NULL, th_right_to_left, param);
        }

        while (1) {
            sleep(1);
            // maybe,, cli thread
        }

        free(pth_lr);
        free(pth_rl);

    } else if ((nm_l == NULL && nm_r != NULL)||(nm_l != NULL && nm_r == NULL)) {

        // tap mode
        netmap* nm = NULL;
        if (nm_l != NULL) {
            nm = nm_l;
        } else if (nm_r != NULL){
            nm = nm_r;
        } else {
        }

        uint16_t rx_qnum;
        rx_qnum = nm->get_rx_qnum();
        pthread_t* pth_tap = (pthread_t*)malloc(sizeof(pthread_t)*rx_qnum);
        if (pth_tap == NULL) {
            PERROR("malloc");
            exit(EXIT_FAILURE);
        }
        memset(pth_tap, 0, sizeof(pthread_t)*rx_qnum);

        for (int i = 0; i < rx_qnum; i++) {
            struct thread_param* param;
            param = (struct thread_param*)malloc(sizeof(struct thread_param));
            if (param == NULL) {
                PERROR("malloc");
                exit(EXIT_FAILURE);
            }
            memset(param, 0, sizeof(struct thread_param));
            param->rx_ringid = i;
            param->tx_ringid = -1;
            param->nm_rx = nm;
            param->nm_tx = NULL;
            param->nm_tap = &v_nm_t;
            pthread_create(&pth_tap[i], NULL, th_tap, param);
        }

        while (1) {
            sleep(1);
            // maybe,, cli thread
        }

        free(pth_tap);

    } else {

        usage(argv[0]);
        exit(EXIT_FAILURE);

    }

    delete nm_l;
    delete nm_r;
    for (auto it : v_nm_t) {
        netmap* nm_tmp = it;
        delete nm_tmp;
    }

    return 0;
}

bool bind_cpu(int cpu, int reverse)
{
    int cpus;
    cpus = sysconf(_SC_NPROCESSORS_ONLN);

    if (reverse) {
        cpu = (cpu - (cpus-1)) * -1;
    }

    cpuset_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu%cpus, &cpuset);

    pthread_t self = pthread_self();    
    if (debug) printf("cpu %d\n", cpu);

    int retval;
    retval = pthread_setaffinity_np(self, sizeof(cpuset_t), &cpuset);

    if (retval == 0) {
        return true;
    } else {
        return false;
    }
}

void*
th_left_to_right(void* param)
{
    pthread_detach(pthread_self());

    struct thread_param* p = (struct thread_param*)param;
    bind_cpu(p->rx_ringid, 0);

    if (debug) printf("left to right\n");

    // loop
    fw_processing(p->nm_rx, p->nm_tx, p->rx_ringid, p->tx_ringid, p->nm_tap);

    free(param);
    return NULL;
}

void*
th_right_to_left(void* param)
{
    pthread_detach(pthread_self());

    struct thread_param* p = (struct thread_param*)param;
    bind_cpu(p->rx_ringid, 1);

    if (debug) printf("right to left\n");

    // loop
    fw_processing(p->nm_rx, p->nm_tx, p->rx_ringid, p->tx_ringid, p->nm_tap);

    free(param);
    return NULL;
}

void*
th_tap(void* param)
{
    pthread_detach(pthread_self());

    struct thread_param* p = (struct thread_param*)param;
    bind_cpu(p->rx_ringid, 0);

    // loop
    tap_processing(p->nm_rx, p->rx_ringid, p->nm_tap);

    free(param);
    return NULL;
}

void
tap_processing(netmap* nm, int ringid, std::vector<netmap*>* v_nm_tap)
{
    int fd;

    struct netmap_ring* rxring = NULL;
    fd = nm->create_nmring_hard_rx(&rxring, ringid);

    if (debug) {
        printf("recv_fd    :%d\n", fd);
        printf("recv_ringid:%d\n", ringid);
        printf("recv_rxring:%p\n", rxring);
    }

    //struct ether_header* eth;
    //size_t ethlen = 0;

    std::vector<struct tap_info> v_tap_info;
    struct tap_info ti;
    memset(&ti, 0, sizeof(ti));

    std::vector<int> v_fds;
    for (auto it : *v_nm_tap) {
        ti.ringid = ringid / it->get_tx_qnum();
        ti.fd = it->get_tx_ring_info_fd(ti.ringid);
        ti.ring = it->get_tx_ring_info_ring(ti.ringid);
        ti.nm = it;
        v_tap_info.push_back(ti);
        memset(&ti, 0, sizeof(ti));
    }

    if (debug) {
        int cur = 0;
        for (auto it : v_tap_info) {
            std::cout << "tap" << cur << "_fd    :" << it.fd     << std::endl;
            std::cout << "tap" << cur << "_ringid:" << it.ringid << std::endl;
            std::cout << "tap" << cur << "_ring  :" << it.ring   << std::endl;
            cur++;
        }
    }

    for (;;) {

        nm->rxsync_block(fd);

        while (rxring->avail > 0) {

            for (auto it : v_tap_info) {
                it.nm->tx_ring_lock(it.ringid);

                if (it.ring->avail == 0) {
                    it.nm->tx_ring_unlock(it.ringid);
                    continue;
                }

                frame_copy(rxring, it.ring);

                it.nm->next(it.ring);
                it.ring->avail--;
                it.nm->tx_ring_unlock(it.ringid);
            }

            nm->next(rxring);
            rxring->avail--;

        }

        for (auto it : v_tap_info) {
            it.nm->tx_ring_lock(it.ringid);
            it.nm->txsync(it.fd, it.ringid);
            it.nm->tx_ring_unlock(it.ringid);
        }

    }

    nm->remove_nmring(ringid);

    return;
}

void
fw_processing(netmap* nm_rx, netmap* nm_tx,
        int rx_ringid, int tx_ringid, std::vector<netmap*>* v_nm_tap)
{
    int tx_fd;
    int rx_fd;

    struct netmap_ring* txring = NULL;
    struct netmap_ring* rxring = NULL;

    rx_fd = nm_rx->create_nmring_hard_rx(&rxring, rx_ringid);
    tx_fd = nm_tx->create_nmring_hard_tx(&txring, tx_ringid);

    if (debug) {
        printf("tx_pointer:%p\n", txring);
        printf("rx_pointer:%p\n", rxring);
        printf("tx_fd:%d\n", tx_fd);
        printf("rx_fd:%d\n", rx_fd);
    }

    std::vector<struct tap_info> v_tap_info;
    struct tap_info ti;
    memset(&ti, 0, sizeof(ti));

    std::vector<int> v_fds;
    for (auto it : *v_nm_tap) {
        ti.ringid = rx_ringid / it->get_tx_qnum();
        ti.fd = it->get_tx_ring_info_fd(ti.ringid);
        ti.ring = it->get_tx_ring_info_ring(ti.ringid);
        ti.nm = it;
        v_tap_info.push_back(ti);
        memset(&ti, 0, sizeof(ti));
    }

    if (debug) {
        int cur = 0;
        for (auto it : v_tap_info) {
            std::cout << "tap" << cur << "_fd    :" << it.fd     << std::endl;
            std::cout << "tap" << cur << "_ringid:" << it.ringid << std::endl;
            std::cout << "tap" << cur << "_ring  :" << it.ring   << std::endl;
            cur++;
        }
    }

    for (;;) {

        //nm_rx->rxsync(rx_fd, rx_ringid);
        nm_rx->rxsync_block(rx_fd);

        while (rxring->avail > 0) {

            if (txring->avail == 0) break;

            for (auto it : v_tap_info) {
                it.nm->tx_ring_lock(it.ringid);

                //std::cout << it.nm->get_ifname() << std::endl;
                //std::cout << it.ring->avail << std::endl;

                if (it.ring->avail == 0) {
                    // XXX ToDo drop count
                    it.nm->tx_ring_unlock(it.ringid);
                    continue;
                }

                frame_copy(rxring, it.ring);

                it.nm->next(it.ring);
                it.ring->avail--;
                it.nm->tx_ring_unlock(it.ringid);
            }

            frame_copy(rxring, txring);

            nm_tx->next(txring);
            txring->avail--;

            nm_rx->next(rxring);
            rxring->avail--;

        }

        nm_tx->txsync(tx_fd, tx_ringid);
        for (auto it : v_tap_info) {
            it.nm->tx_ring_lock(it.ringid);
            it.nm->txsync(it.fd, it.ringid);
            it.nm->tx_ring_unlock(it.ringid);
        }

    }

    nm_rx->remove_nmring(rx_ringid);
    nm_tx->remove_nmring(tx_ringid);

    return;
}

inline void
frame_copy(struct netmap_ring* rxring, struct netmap_ring* txring)
{
    struct netmap_slot* rx_slot = 
         ((netmap_slot*)&rxring->slot[rxring->cur]);

    struct netmap_slot* tx_slot = 
         ((netmap_slot*)&txring->slot[txring->cur]);

    struct ether_header* rx_eth = 
        (struct ether_header*)NETMAP_BUF(rxring, rx_slot->buf_idx);

    struct ether_header* tx_eth = 
        (struct ether_header*)NETMAP_BUF(txring, tx_slot->buf_idx);


    /*
    ((netmap_slot*)&rxring->slot[rxring->cur])->len = 
        ((netmap_slot*)&txring->slot[txring->cur])->len;
    */

    tx_slot->len = rx_slot->len;
    memcpy(tx_eth, rx_eth, tx_slot->len);

    /*
    if (debug) printf("------\n");
    if (debug) memdump(rx_eth, rx_slot->len);
    */

    return;
}

void
usage(char* prog_name)
{
    printf("%s\n", prog_name);
    printf("  Must..\n");
    printf("    -l [ifname] (left interface)\n");
    printf("    -r [ifname] (right interface)\n");
    printf("    -t [ifname,ifname,ifname...])\n");
    printf("  Option..\n");
    printf("    -h/? : help usage information\n");
    printf("    -v : verbose mode\n");
    printf("\n");
    return;
}
