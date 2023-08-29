#include "udp.h"

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ip.h"
#include "platform.h"
#include "util.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

// see https://tools.ietf.org/html/rfc6335
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

// Pseudo header for UDP checksumming.
struct pseudo_hdr {
    // IP addresses.
    uint32_t src;
    uint32_t dst;
    // Zero.
    uint8_t zero;
    // Protocol.
    // See IP_PROTOCOL_* in ip.h
    uint8_t protocol;
    // UDP Header + Data length.
    uint16_t len;
};

// UDP header.
struct udp_hdr {
    // Port numbers.
    uint16_t src;
    uint16_t dst;
    // UDP Header + Data length.
    uint16_t len;
    // Checksum.
    uint16_t sum;
};

// UDP Protocol Control Block.
struct udp_pcb {
    int state;
    struct ip_endpoint local;
    // Receive queue
    struct queue_head queue;
    struct sched_ctx ctx;
};

struct udp_queue_entry {
    struct ip_endpoint foreign;
    // UDP payload length.
    uint16_t len;
    // UDP payload.
    uint8_t data[];
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE];

static void udp_dump(const uint8_t *data, size_t len) {
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

//
// UDP Protocol Control Block (PCB)
//
// NOTE: UDP PCB functions must be called after mutex locked

static struct udp_pcb *udp_pcb_alloc(void) {
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_FREE) {
            pcb->state = UDP_PCB_STATE_OPEN;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }

    return NULL;
}

static void udp_pcb_release(struct udp_pcb *pcb) {
    struct queue_entry *entry;

    pcb->state = UDP_PCB_STATE_CLOSING;
    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }

    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;
    while (1) {
        entry = queue_pop(&pcb->queue);
        if (!entry) {
            break;
        }
        memory_free(entry);
    }
}

// Select the PCB with the specified address and port.
static struct udp_pcb *udp_pcb_select(ip_addr_t addr, uint16_t port) {
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            if (pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) {
                if (pcb->local.port == port) {
                    return pcb;
                }
            }
        }
    }

    return NULL;
}

// To prevent the user from directly modifying the PCB fields, the user interface is through socket IDs, which are essentially
// indices into the 'pcbs' array.
static int udp_pcb_id(struct udp_pcb *pcb) {
    return indexof(pcbs, pcb);
}

static struct udp_pcb *udp_pcb_get(int id) {
    struct udp_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs)) {
        /* out of range */
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN) {
        return NULL;
    }
    return pcb;
}

static void udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface) {
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;
    // For debug log.
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }

    hdr = (struct udp_hdr *)data;
    if (ntoh16(hdr->len) != len) {
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)", ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst), len, len - sizeof(*hdr));
    udp_dump(data, len);

    mutex_lock(&mutex);
    pcb = udp_pcb_select(dst, hdr->dst);
    if (!pcb) {
        mutex_unlock(&mutex);
        return;
    }
    entry = memory_alloc(sizeof(*entry) + len);
    entry->foreign.addr = src;
    entry->foreign.port = hdr->src;
    entry->len = len - sizeof(*hdr);
    memcpy(entry->data, hdr + 1, entry->len);

    if (!queue_push(&pcb->queue, entry)) {
        mutex_unlock(&mutex);
        errorf("queue_push() failure");
        return;
    }

    debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);

    sched_wakeup(&pcb->ctx);
    mutex_unlock(&mutex);
}

ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len) {
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t total;
    uint16_t psum = 0;
    // For debug log.
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
        errorf("too long");
        return -1;
    }

    hdr = (struct udp_hdr *)buf;
    hdr->src = src->port;
    hdr->dst = dst->port;
    total = sizeof(*hdr) + len;
    hdr->len = hton16(total);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len);
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);

    debugf("%s => %s, len=%zu (payload=%zu)", ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
    udp_dump((uint8_t *)hdr, total);

    if (ip_output(IP_PROTOCOL_UDP, (uint8_t *)hdr, total, src->addr, dst->addr) == -1) {
        errorf("ip_output() failure");
        return -1;
    }

    return len;
}

static void event_handler(void *arg) {
    struct udp_pcb *pcb;

    (void)arg;
    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

int udp_init(void) {
    if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }

    net_event_subscribe(event_handler, NULL);

    return 0;
}

//
// UDP User Commands
//

int udp_open(void) {
    struct udp_pcb *pcb;
    int sock;

    mutex_lock(&mutex);
    pcb = udp_pcb_alloc();
    if (!pcb) {
        errorf("udp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    sock = udp_pcb_id(pcb);
    mutex_unlock(&mutex);

    return sock;
}

int udp_close(int id) {
    struct udp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("Not found");
        mutex_unlock(&mutex);
        return -1;
    }
    udp_pcb_release(pcb);
    mutex_unlock(&mutex);

    return 0;
}

int udp_bind(int id, struct ip_endpoint *local) {
    struct udp_pcb *pcb, *found;
    // For debug log.
    char ep1[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("Not found");
        mutex_unlock(&mutex);
        return -1;
    }
    found = udp_pcb_select(local->addr, local->port);
    if (found) {
        errorf("already bound, id=%d, local=%s", id, ip_endpoint_ntop(&found->local, ep1, sizeof(ep1)));
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->local = *local;
    mutex_unlock(&mutex);

    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));

    return 0;
}

ssize_t udp_sendto(int id, uint8_t *data, size_t len, struct ip_endpoint *foreign) {
    struct udp_pcb *pcb;
    struct ip_endpoint local;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint32_t p;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("Not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    // Source IP and port are optional; auto-select them if they are not specified.
    // Select local address.
    local.addr = pcb->local.addr;
    if (local.addr == IP_ADDR_ANY) {
        iface = ip_route_get_iface(foreign->addr);
        if (!iface) {
            errorf("iface not found that can reach foreign address, addr=%s", ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
        local.addr = iface->unicast;
        debugf("select local address, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
    }
    // Select local port.
    if (!pcb->local.port) {
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
            if (!udp_pcb_select(local.addr, hton16(p))) {
                pcb->local.port = hton16(p);
                debugf("dynamic assign local port, port=%d", p);
                break;
            }
        }
        if (!pcb->local.port) {
            debugf("failed to dynamic assign local port, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
    }
    local.port = pcb->local.port;
    mutex_unlock(&mutex);

    return udp_output(&local, foreign, data, len);
}

ssize_t udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign) {
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;
    ssize_t len;
    int err;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("Not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }

    while (1) {
        entry = queue_pop(&pcb->queue);
        if (entry) {
            break;
        }
        /* Wait to be woken up by sched_wakeup() or shced_interrupt() */
        err = sched_sleep(&pcb->ctx, &mutex, NULL);
        if (err) {
            debugf("interrupted");
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }

        if (pcb->state == UDP_PCB_STATE_CLOSING) {
            debugf("closed");
            udp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
    }
    // entry found.

    mutex_unlock(&mutex);
    // Discard the foreign endpoint if `foreign` is NULL.
    if (foreign) {
        *foreign = entry->foreign;
    }
    len = MIN(size, entry->len);
    memcpy(buf, entry->data, len);
    memory_free(entry);

    return len;
}
