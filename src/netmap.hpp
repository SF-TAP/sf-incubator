
#ifndef __netmap_hpp__
#define __netmap_hpp__

#include "common.hpp"

#include <iostream>
#include <map>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef POLL
#include <poll.h>
#else
#include <sys/select.h>
#endif


#include <net/if.h>
#include <net/if_dl.h>
#include <net/ethernet.h>

#include <net/netmap.h>
#include <net/netmap_user.h>


class netmap
{
public:

    // constructor
    netmap();
    // destructor
    virtual ~netmap();

    struct ring_info {
        int fd;
        int ringid;
        char* map;
        struct netmap_ring* ring;
        volatile int lock;
    };


    // control methods
    bool open_if(const std::string& ifname);
    bool open_if(const char* ifname);
    inline bool rxsync(int fd, int ringid);
    inline bool txsync(int fd, int ringid);
    inline bool rxsync_block(int fd);
    inline bool txsync_block(int fd);
    inline bool rxsync_pollall();
    inline bool txsync_pollall();
    int create_nmring_hard_tx(struct netmap_ring** ring, int qnum);
    int create_nmring_hard_rx(struct netmap_ring** ring, int qnum);
    int create_nmring_soft_tx(struct netmap_ring** ring, int qnum);
    int create_nmring_soft_rx(struct netmap_ring** ring, int qnum);
    bool remove_nmring(int qnum);

    // utils methods
    void dump_nmr();
    bool set_promisc();
    bool unset_promisc();

    // netmap getter
    char* get_ifname();
    uint16_t get_tx_qnum();
    uint16_t get_rx_qnum();
    struct ether_addr* get_mac();
    inline void next(struct netmap_ring* ring);
    inline size_t get_ethlen(struct netmap_ring* ring);
    inline void set_ethlen(struct netmap_ring* ring, size_t size);
    inline uint32_t get_cursor(struct netmap_ring* ring);
    inline struct netmap_slot* get_slot(struct netmap_ring* ring);
    inline struct ether_header* get_eth(struct netmap_ring* ring);
    int get_tx_ring_info_fd(int ringid);
    char* get_tx_ring_info_map(int ringid);
    struct netmap_ring* get_tx_ring_info_ring(int ringid);
    int get_rx_ring_info_fd(int ringid);
    char* get_rx_ring_info_map(int ringid);
    struct netmap_ring* get_rx_ring_info_ring(int ringid);

    inline void tx_ring_lock(int ringid);
    inline void tx_ring_unlock(int ringid);
    inline void rx_ring_lock(int ringid);
    inline void rx_ring_unlock(int ringid);


private:
    uint32_t nm_version;
    uint16_t nm_rx_qnum;
    uint16_t nm_tx_qnum;
    uint32_t nm_memsize;
    char nm_ifname[IFNAMSIZ];
    struct ether_addr nm_mac;
    uint32_t nm_oui;
    uint32_t nm_bui;
#ifdef POLL
    struct pollfd* rx_pollfds;
    struct pollfd* tx_pollfds;
#endif
    struct nmreq nm_nmr;
    pthread_mutex_t lock_ring_info;
    std::map<int, struct ring_info*> tx_ring_info;
    std::map<int, struct ring_info*> rx_ring_info;

    int _create_nmring(struct netmap_ring** ring, int qnum, int rxtx, int swhw);
};

netmap::netmap()
{
    nm_version = 0;
    nm_rx_qnum = 0;
    nm_tx_qnum = 0;
    nm_memsize = 0;
    memset(nm_ifname, 0, sizeof(nm_ifname));
    memset(&nm_mac, 0, sizeof(nm_mac));
    nm_oui = 0;
    nm_bui = 0;
#ifdef POLL
    rx_pollfds = NULL;
    tx_pollfds = NULL;
#endif

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
    pthread_mutex_init(&lock_ring_info, &attr);
}

netmap::~netmap()
{
    std::map<int, struct ring_info*>::iterator it;

    for (it = tx_ring_info.begin(); it != tx_ring_info.end(); it++) {
        struct ring_info* tmp_value = it->second;
        if (tmp_value->map != NULL) {
            if (munmap(tmp_value->map, nm_memsize) != 0) {
                exit(EXIT_FAILURE);
            }
            tmp_value->map = NULL;
            close(tmp_value->fd);
            free(tmp_value);
        }
    }
    tx_ring_info.clear();

    for (it = rx_ring_info.begin(); it != rx_ring_info.end(); it++) {
        struct ring_info* tmp_value = it->second;
        if (tmp_value->map != NULL) {
            if (munmap(tmp_value->map, nm_memsize) != 0) {
                exit(EXIT_FAILURE);
            }
            tmp_value->map = NULL;
            close(tmp_value->fd);
            free(tmp_value);
        }
    }
    rx_ring_info.clear();

    pthread_mutex_destroy(&lock_ring_info);

#ifdef POLL
    free(rx_pollfds);
    free(tx_pollfds);
#endif

}

bool
netmap::open_if(const std::string& ifname)
{
    return open_if(ifname.c_str());
}

bool
netmap::open_if(const char* ifname)
{
    int fd;
    fd = open("/dev/netmap", O_RDWR);
    if (fd < 0) {
        PERROR("open");
        MESG("Unable to open /dev/netmap");
        return false;
    }
    memset(&nm_nmr, 0, sizeof(nm_nmr));
    nm_version = 4;
    nm_nmr.nr_version = nm_version;
    strncpy(nm_ifname, ifname, strlen(ifname));
    strncpy(nm_nmr.nr_name, ifname, strlen(ifname));
    if (ioctl(fd, NIOCGINFO, &nm_nmr) < 0) {
        PERROR("ioctl");
        MESG("unabe to get interface info for %s", ifname);
        memset(&nm_nmr, 0, sizeof(nm_nmr));
        close(fd);
        return false;
    }
    nm_tx_qnum = nm_nmr.nr_tx_rings;
    nm_rx_qnum = nm_nmr.nr_rx_rings;
    nm_memsize = nm_nmr.nr_memsize;
    close(fd);

    //getmac
    struct ifaddrs *ifs;
    struct ifaddrs *ifp;
    struct sockaddr_dl* dl;

    if (getifaddrs(&ifs) != 0) {
        PERROR("getifaddrs");
        MESG("unabe to get interface info for %s", ifname);
        memset(&nm_nmr, 0, sizeof(nm_nmr));
        return false;
    }

    for (ifp=ifs; ifp; ifp=ifp->ifa_next) {
        int ifp_family = ifp->ifa_addr->sa_family;

        if (ifp->ifa_addr == NULL) {
            continue;
        } else if (ifp_family != AF_LINK) {
            continue;
        }

        dl = (struct sockaddr_dl*)ifp->ifa_addr;

        if (strncmp(ifname, dl->sdl_data, dl->sdl_nlen) == 0) {
            memcpy(&nm_mac, LLADDR(dl), ETHER_ADDR_LEN);
            break;
        }
    }
    freeifaddrs(ifs);

    nm_oui = nm_mac.octet[0]<<16 | nm_mac.octet[1]<<8 | nm_mac.octet[2];
    nm_bui = nm_mac.octet[3]<<16 | nm_mac.octet[4]<<8 | nm_mac.octet[5];
    if (debug) printf("%s_mac_address->%06x:%06x\n", nm_ifname, nm_oui, nm_bui);
    if (nm_oui == 0 && nm_bui == 0) {
        return false;
    }

#ifdef POLL
    rx_pollfds = (struct pollfd*)malloc(sizeof(struct pollfd) * nm_rx_qnum);
    tx_pollfds = (struct pollfd*)malloc(sizeof(struct pollfd) * nm_tx_qnum);
#endif

    return true;
}

inline bool
netmap::rxsync(int fd, int ringid)
{
    if (ioctl(fd, NIOCRXSYNC, ringid) == -1) {
        PERROR("ioctl");
        return false;
    } else {
        return true;
    }
}

#ifdef POLL
inline bool
netmap::rxsync_pollall()
{
    int retval = poll(rx_pollfds, nm_rx_qnum, -1);
    if (retval == 0) {
        // timeout
        return false;
    } else if (retval < 0) {
        PERROR("poll");
        return false;
    } else {
        return true;
    }
}

inline bool
netmap::txsync_pollall()
{
    int retval = poll(tx_pollfds, nm_tx_qnum, -1);
    if (retval == 0) {
        // timeout
        return false;
    } else if (retval < 0) {
        PERROR("poll");
        return false;
    } else {
        return true;
    }
}
#endif

inline bool
netmap::rxsync_block(int fd)
{
#ifdef POLL

    int retval;
    struct pollfd x[1];
    x[0].fd = fd;
    x[0].events = POLLIN;
#define POLL_BLOCK -1
    retval = poll(x, 1, POLL_BLOCK);
#undef POLL_BLOCK
    if (retval == 0) {
        // timeout
        return false;
    } else if (retval < 0) {
        PERROR("poll");
        return false;
    } else {
        return true;
    }

#else 

    int retval;
    fd_set s_fd;
    FD_ZERO(&s_fd);
    FD_SET(fd, &s_fd);
    retval = select(fd+1, &s_fd, NULL, NULL, NULL);
    if (retval == 0) {
        //timeout
        return false;
    } else if (retval < 0) {
        PERROR("select");
        return false;
    } else {
        return true;
    }

#endif
}

inline bool
netmap::txsync(int fd, int ringid)
{
    if (ioctl(fd, NIOCTXSYNC, ringid) == -1) {
        PERROR("ioctl");
        return false;
    } else {
        return true;
    }
}

inline bool
netmap::txsync_block(int fd)
{
#ifdef POLL
    int retval;
    struct pollfd x[1];
    x[0].fd = fd;
    x[0].events = POLLOUT;
#define POLL_BLOCK -1
    retval = poll(x, 1, POLL_BLOCK);
#undef POLL_BLOCK
    if (retval == 0) {
        // timeout
        return false;
    } else if (retval < 0) {
        PERROR("poll");
        return false;
    } else {
        return true;
    }
#else 
    int retval;
    fd_set s_fd;
    FD_ZERO(&s_fd);
    FD_SET(fd, &s_fd);
    retval = select(fd+1, NULL, &s_fd, NULL, NULL);
    if (retval == 0) {
        //timeout
        return false;
    } else if (retval < 0) {
        PERROR("select");
        return false;
    } else {
        return true;
    }
#endif
}

inline uint32_t
netmap::get_cursor(struct netmap_ring* ring)
{
    return ring->cur;
}

inline struct netmap_slot*
netmap::get_slot(struct netmap_ring* ring)
{
    return &ring->slot[ring->cur];
}

inline void
netmap::next(struct netmap_ring* ring)
{
    ring->cur = NETMAP_RING_NEXT(ring, ring->cur);
    return;
}

inline struct ether_header*
netmap::get_eth(struct netmap_ring* ring)
{
    struct netmap_slot* slot = get_slot(ring);
    return (struct ether_header*)NETMAP_BUF(ring, slot->buf_idx);
}

inline size_t
netmap::get_ethlen(struct netmap_ring* ring)
{
    struct netmap_slot* slot = get_slot(ring);
    return slot->len;
}

int
netmap::get_tx_ring_info_fd(int ringid)
{
    pthread_mutex_lock(&lock_ring_info);
    int tmp_fd = tx_ring_info[ringid]->fd;
    pthread_mutex_unlock(&lock_ring_info);

    if (tmp_fd == 0) {
        return -1;
    } else {
        return tmp_fd;
    }
}

char*
netmap::get_tx_ring_info_map(int ringid)
{
    pthread_mutex_lock(&lock_ring_info);
    char* tmp_map = tx_ring_info[ringid]->map;
    pthread_mutex_unlock(&lock_ring_info);

    return tmp_map;
}

struct netmap_ring*
netmap::get_tx_ring_info_ring(int ringid)
{
    pthread_mutex_lock(&lock_ring_info);
    struct netmap_ring* tmp_ring = tx_ring_info[ringid]->ring;
    pthread_mutex_unlock(&lock_ring_info);
    return tmp_ring;
}

int
netmap::get_rx_ring_info_fd(int ringid)
{
    pthread_mutex_lock(&lock_ring_info);
    int tmp_fd = rx_ring_info[ringid]->fd;
    pthread_mutex_unlock(&lock_ring_info);

    if (tmp_fd == 0) {
        return -1;
    } else {
        return tmp_fd;
    }
}

char*
netmap::get_rx_ring_info_map(int ringid)
{
    pthread_mutex_lock(&lock_ring_info);
    char* tmp_map = rx_ring_info[ringid]->map;
    pthread_mutex_unlock(&lock_ring_info);

    return tmp_map;
}

struct netmap_ring*
netmap::get_rx_ring_info_ring(int ringid)
{
    pthread_mutex_lock(&lock_ring_info);
    struct netmap_ring* tmp_ring = rx_ring_info[ringid]->ring;
    pthread_mutex_unlock(&lock_ring_info);
    return tmp_ring;
}


inline void
netmap::tx_ring_lock(int ringid)
{
    while (__sync_lock_test_and_set(&tx_ring_info[ringid]->lock, 1)) {
        //Compare-And-Swap(CAS)の命令は重いので単にループするだけのwhile
        //を挟むことで，CASのループを少なくする．
        //アダプティブロックにするならCAS-loop/while(lock)の回数を決めて
        //sched_yield()を呼ぶこと．
        while (tx_ring_info[ringid]->lock) {};
    }

    /*
    while (__sync_bool_compare_and_swap(&tx_ring_info[ringid]->lock, 0, 1) == 0) {
        asm volatile("lfence" ::: "memory");
        sched_yield();
    }
    */
    return;
}

inline void
netmap::tx_ring_unlock(int ringid)
{
    __sync_lock_release(&tx_ring_info[ringid]->lock);

    /*
    tx_ring_info[ringid]->lock = 0;
    asm volatile("sfence" ::: "memory");
    */
    return;
}

inline void
netmap::rx_ring_lock(int ringid)
{
    while (__sync_lock_test_and_set(&rx_ring_info[ringid]->lock, 1)) {
        //Compare-And-Swap(CAS)の命令は重いので単にループするだけのwhile
        //を挟むことで，CASのループを少なくする．
        //アダプティブロックにするならCAS-loop/while(lock)の回数を決めて
        //sched_yield()を呼ぶこと．
        while (rx_ring_info[ringid]->lock) {};
    }

    /*
    while (__sync_bool_compare_and_swap(&rx_ring_info[ringid]->lock, 0, 1) == 0) {
        asm volatile("lfence" ::: "memory");
        sched_yield();
    }
    */
    return;
}

inline void
netmap::rx_ring_unlock(int ringid)
{
    __sync_lock_release(&rx_ring_info[ringid]->lock);

    /*
    rx_ring_info[ringid]->lock = 0;
    asm volatile("sfence" ::: "memory");
    */
    return;
}



inline void
netmap::set_ethlen(struct netmap_ring* ring, size_t size)
{
    struct netmap_slot* slot = get_slot(ring);
    slot->len = size;
}

inline struct ether_addr*
netmap::get_mac()
{
    return &nm_mac;
}


void
netmap::dump_nmr()
{
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
    printf("-----\n");
    printf("nr_name     : %s\n", nm_nmr.nr_name);
    printf("nr_varsion  : %d\n", nm_nmr.nr_version);
    printf("nr_offset   : %d\n", nm_nmr.nr_offset);
    printf("nr_memsize  : %d\n", nm_nmr.nr_memsize);
    printf("nr_tx_slots : %d\n", nm_nmr.nr_tx_slots);
    printf("nr_rx_slots : %d\n", nm_nmr.nr_rx_slots);
    printf("nr_tx_rings : %d\n", nm_nmr.nr_tx_rings);
    printf("nr_rx_rings : %d\n", nm_nmr.nr_rx_rings);
    printf("nr_ringid   : %d\n", nm_nmr.nr_ringid);
    printf("nr_cmd      : %d\n", nm_nmr.nr_cmd);
    printf("nr_arg1     : %d\n", nm_nmr.nr_arg1);
    printf("nr_arg2     : %d\n", nm_nmr.nr_arg2);
    printf("nr_spare2[0]: %x\n", nm_nmr.spare2[0]);
    printf("nr_spare2[1]: %x\n", nm_nmr.spare2[1]);
    printf("nr_spare2[2]: %x\n", nm_nmr.spare2[2]);
    printf("-----\n");
    return;
}

char*
netmap::get_ifname()
{
    return nm_ifname;
}

uint16_t
netmap::get_tx_qnum()
{
    return nm_tx_qnum;
}

uint16_t
netmap::get_rx_qnum()
{
    return nm_rx_qnum;
}

bool
netmap::set_promisc()
{
    int fd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    char* ifname = get_ifname();

    strncpy(ifr.ifr_name, ifname, strlen(ifname));
    if (ioctl(fd, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
        PERROR("ioctl");
        MESG("failed to get interface status");
        close(fd);
        return false;
    }

    //printf("%04x%04x\n", ifr.ifr_flagshigh, ifr.ifr_flags & 0xffff);

    int flags = (ifr.ifr_flagshigh << 16) | (ifr.ifr_flags & 0xffff);

    flags |= IFF_PPROMISC;
    ifr.ifr_flags = flags & 0xffff;
    ifr.ifr_flagshigh = flags >> 16;

    //printf("%04x%04x\n", ifr.ifr_flagshigh, ifr.ifr_flags & 0xffff);

    if (ioctl(fd, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
        PERROR("ioctl");
        MESG("failed to set interface to promisc");
        close(fd);
        return false;
    }
    close(fd);

    return true;
}

bool
netmap::unset_promisc()
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    char* ifname = get_ifname();
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, strlen(ifname));
    if (ioctl (fd, SIOCGIFFLAGS, &ifr) != 0) {
        PERROR("ioctl");
        MESG("failed to get interface status");
        close(fd);
        return false;
    }
    
    ifr.ifr_flags &= ~IFF_PROMISC;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
        PERROR("ioctl");
        MESG("failed to set interface to promisc");
        close(fd);
        return false;
    }
    close(fd);
    
    return true;
}


#define NETMAP_RX 0
#define NETMAP_TX 1
int
netmap::_create_nmring(struct netmap_ring** ring, int qnum, int rxtx, int swhw)
{
    int fd;

    struct nmreq nmr;
    struct netmap_if* nmif;

    fd = open("/dev/netmap", O_RDWR);
    if (fd < 0) {
        perror("open");
        MESG("unable to open /dev/netmap");
        return -1;
    }

    memset (&nmr, 0, sizeof(nmr));
    //printf("nm_ifname:%s\n", nm_ifname);
    strncpy (nmr.nr_name, nm_ifname, strlen(nm_ifname));
    nmr.nr_version = nm_version;
    nmr.nr_ringid = (swhw | qnum);
    //printf("ringid:%x\n", nmr.nr_ringid);
    // swhw : soft ring or hard ring
    //NETMAP_HW_RING 0x4000
    //NETMAP_SW_RING 0x2000

    if (ioctl(fd, NIOCREGIF, &nmr) < 0) {
        perror("ioctl");
        MESG("unable to register interface %s", nm_ifname);
        close(fd);
        return -1;
    }

    char* mem = (char*)mmap(NULL, nmr.nr_memsize,
            PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        MESG("unable to mmap");
        close(fd);
        return -1;
    }

    nmif = NETMAP_IF(mem, nmr.nr_offset);
    struct netmap_ring* tmp_ring;

    if (ring == NULL) {

        if (rxtx == NETMAP_TX) {
            tmp_ring = NETMAP_TXRING(nmif, qnum);
        } else if (rxtx == NETMAP_RX) {
            tmp_ring = NETMAP_RXRING(nmif, qnum);
        } else {
            if (munmap(mem, nmr.nr_memsize) != 0) {
                PERROR("munmap");
            }
            MESG("class broken..??");
            close(fd);
            return -1;
        }

    } else {

        if (rxtx == NETMAP_TX) {
            *ring = NETMAP_TXRING(nmif, qnum);
        } else if (rxtx == NETMAP_RX) {
            *ring = NETMAP_RXRING(nmif, qnum);
        } else {
            if (munmap(mem, nmr.nr_memsize) != 0) {
                PERROR("munmap");
            }
            MESG("class broken..??");
            close(fd);
            return -1;
        }

    }

    if (rxtx == NETMAP_TX) {

        struct ring_info* mv = (struct ring_info*)malloc(sizeof(struct ring_info));
        mv->fd = fd;
        mv->ringid = qnum;
        mv->map = mem;
        if (ring == NULL) {
            mv->ring = tmp_ring;
        } else {
            mv->ring = *ring;
        }
        mv->lock = 0;

        pthread_mutex_lock(&lock_ring_info);
        tx_ring_info[qnum] = mv; 
        pthread_mutex_unlock(&lock_ring_info);

#ifdef POLL
        tx_pollfds[qnum].fd = fd;
        tx_pollfds[qnum].events = POLLOUT;
#endif

    } else if (rxtx == NETMAP_RX) {

        struct ring_info* mv = (struct ring_info*)malloc(sizeof(struct ring_info));
        mv->fd = fd;
        mv->ringid = qnum;
        mv->map = mem;
        if (ring == NULL) {
            mv->ring = tmp_ring;
        } else {
            mv->ring = *ring;
        }
        mv->lock = 0;

        pthread_mutex_lock(&lock_ring_info);
        rx_ring_info[qnum] = mv; 
        pthread_mutex_unlock(&lock_ring_info);

#ifdef POLL
        rx_pollfds[qnum].fd = fd;
        rx_pollfds[qnum].events = POLLIN;
#endif

    } else {
    }


    return fd;
}

int
netmap::create_nmring_hard_tx(struct netmap_ring** ring, int qnum)
{
    int rxtx = NETMAP_TX;
    int swhw = NETMAP_HW_RING;
    return _create_nmring(ring, qnum, rxtx, swhw);
}

int
netmap::create_nmring_hard_rx(struct netmap_ring** ring, int qnum)
{
    int rxtx = NETMAP_RX;
    int swhw = NETMAP_HW_RING;
    return _create_nmring(ring, qnum, rxtx, swhw);
}

int
netmap::create_nmring_soft_tx(struct netmap_ring** ring, int qnum)
{
    int rxtx = NETMAP_TX;
    int swhw = NETMAP_SW_RING;
    return _create_nmring(ring, qnum, rxtx, swhw);
}

int
netmap::create_nmring_soft_rx(struct netmap_ring** ring, int qnum)
{
    int rxtx = NETMAP_RX;
    int swhw = NETMAP_SW_RING;
    return _create_nmring(ring, qnum, rxtx, swhw);
}

bool
netmap::remove_nmring(int qnum)
{
    pthread_mutex_lock(&lock_ring_info);

    std::map<int, struct ring_info*>::iterator it;
    struct ring_info* tmp_value;

    it = tx_ring_info.find(qnum);
    if(it == tx_ring_info.end()) {
        goto REMOVE_FAIL;
    }
    tmp_value = it->second;
    if (tmp_value->map != NULL) {
        if (munmap(tmp_value->map, nm_memsize) != 0) {
            PERROR("munmap");
            goto REMOVE_FAIL;
        }
        tmp_value->map = NULL;
        close(tmp_value->fd);
        free(tmp_value);
    }
    tx_ring_info.erase(it);

    it = rx_ring_info.find(qnum);
    if(it == rx_ring_info.end()) {
        goto REMOVE_FAIL;
    }
    tmp_value = it->second;
    if (tmp_value->map != NULL) {
        if (munmap(tmp_value->map, nm_memsize) != 0) {
            PERROR("munmap");
            goto REMOVE_FAIL;
        }
        tmp_value->map = NULL;
        close(tmp_value->fd);
        free(tmp_value);
    }
    rx_ring_info.erase(it);

    pthread_mutex_unlock(&lock_ring_info);
    return true;

    REMOVE_FAIL:
    pthread_mutex_unlock(&lock_ring_info);
    return false;
}

#endif
