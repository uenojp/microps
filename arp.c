#include "arp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "ether.h"
#include "ip.h"
#include "net.h"
#include "platform.h"
#include "util.h"

// see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt
#define ARP_HRD_ETHER 0x0001
// NOTE: use same value as the Ethernet types.
#define ARP_PRO_IP ETHER_TYPE_IP

// Operation codes.
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_CACHE_SIZE 32

#define ARP_CACHE_STATE_FREE 0
// In a querying state where the hardware address is not yet determined.
#define ARP_CACHE_STATE_INCOMPLETE 1
// In a state where the hardware address has been resolved.
#define ARP_CACHE_STATE_RESOLVED 2
// TBD: In a state where the hardware address is statically configured.
#define ARP_CACHE_STATE_STATIC 3

// ARP header.
struct arp_hdr {
    // Hardware Address Space(type).
    uint16_t hrd;
    // Protocol Address Space(type).
    uint16_t pro;
    // Hardware Address Length.
    uint8_t hln;
    // Protocol Address Length.
    uint8_t pln;
    // Operation Code, such as Arp Request or Arp Reply.
    uint16_t op;
};

// ARP header for Ethernet and IPv4.
// NOTE: Using an array of uint8 instead of ip_addr_t to store the address, due to padding issues.
struct arp_ether_ip {
    struct arp_hdr hdr;
    // Sender hardware address (MAC address).
    uint8_t sha[ETHER_ADDR_LEN];
    // Sender protocol address (IP address).
    uint8_t spa[IP_ADDR_LEN];
    // Target hardware address (MAC address).
    uint8_t tha[ETHER_ADDR_LEN];
    // Target protocol address (IP address).
    uint8_t tpa[IP_ADDR_LEN];
};

struct arp_cache {
    unsigned char state;
    // Protocol Address.
    ip_addr_t pa;
    // Hardware Address.
    uint8_t ha[ETHER_ADDR_LEN];
    // Last update time.
    struct timeval timestamp;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE];

static char *arp_opcode_ntoa(uint16_t opcode) {
    switch (ntoh16(opcode)) {
        case ARP_OP_REQUEST:
            return "Request";
        case ARP_OP_REPLY:
            return "Reply";
    }
    return "Unknown";
}

static void arp_dump(const uint8_t *data, size_t len) {
    struct arp_ether_ip *arp;
    ip_addr_t spa, tpa;
    char addr[128];

    arp = (struct arp_ether_ip *)data;
    flockfile(stderr);
    fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(arp->hdr.hrd));
    fprintf(stderr, "        pro: 0x%04x\n", ntoh16(arp->hdr.pro));
    fprintf(stderr, "        hln: %u\n", arp->hdr.hln);
    fprintf(stderr, "        pln: %u\n", arp->hdr.pln);
    fprintf(stderr, "         op: %u (%s)\n", ntoh16(arp->hdr.op), arp_opcode_ntoa(arp->hdr.op));
    fprintf(stderr, "        sha: %s\n", ether_addr_ntop(arp->sha, addr, sizeof(addr)));
    memcpy(&spa, arp->spa, sizeof(spa));
    fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "        tha: %s\n", ether_addr_ntop(arp->tha, addr, sizeof(addr)));
    memcpy(&tpa, arp->tpa, sizeof(tpa));
    fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

//
// ARP Cache
//
// NOTE: ARP Cache functions must be called after mutex locked

static void arp_cache_delete(struct arp_cache *cache) {
    // For debug log.
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = 0;
    memset(cache->ha, 0, sizeof(cache->ha));
    timerclear(&cache->timestamp);
}

static struct arp_cache *arp_cache_alloc(void) {
    struct arp_cache *entry;
    struct arp_cache *oldest = NULL;

    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state == ARP_CACHE_STATE_FREE) {
            return entry;
        }
        if (!oldest || timercmp(&entry->timestamp, &oldest->timestamp, <)) {
            oldest = entry;
        }
    }
    // no free entry

    arp_cache_delete(oldest);

    return oldest;
}

static struct arp_cache *arp_cache_select(ip_addr_t pa) {
    struct arp_cache *entry;

    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state != ARP_CACHE_STATE_FREE && entry->pa == pa) {
            return entry;
        }
    }

    return NULL;
}

// Update the cache entry for the protocol address to RESOLVED.
static struct arp_cache *arp_cache_update(ip_addr_t pa, const uint8_t *ha) {
    struct arp_cache *cache;
    // For debug log.
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    cache = arp_cache_select(pa);
    if (!cache) {
        return NULL;
    }
    cache->state = ARP_CACHE_STATE_RESOLVED;
    gettimeofday(&cache->timestamp, NULL);

    debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));

    return cache;
}

static struct arp_cache *arp_cache_insert(ip_addr_t pa, const uint8_t *ha) {
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    cache = arp_cache_alloc();
    if (!cache) {
        errorf("no free entry");
        return NULL;
    }

    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);

    debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));

    return cache;
}

static int arp_request(struct net_iface *iface, ip_addr_t tpa) {
    struct arp_ether_ip request;

    request.hdr.hrd = hton16(ARP_HRD_ETHER);
    request.hdr.pro = hton16(ARP_PRO_IP);
    request.hdr.hln = ETHER_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = hton16(ARP_OP_REQUEST);

    memcpy(request.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(request.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memset(request.tha, 0., ETHER_ADDR_LEN);
    memcpy(request.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(request));
    arp_dump((uint8_t *)&request, sizeof(request));

    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&request, sizeof(request), iface->dev->broadcast);
}

static int arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst) {
    struct arp_ether_ip reply;

    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);

    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));

    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

static void arp_input(const uint8_t *data, size_t len, struct net_device *dev) {
    struct arp_ether_ip *arp;
    ip_addr_t spa, tpa;
    struct net_iface *iface;
    int merge = 0;

    if (len < sizeof(*arp)) {
        errorf("too short");
        return;
    }

    arp = (struct arp_ether_ip *)data;
    // Checking the hardware address.
    if (ntoh16(arp->hdr.hrd) != ARP_HRD_ETHER || arp->hdr.hln != ETHER_ADDR_LEN) {
        errorf("unsupported hardware address");
        return;
    }
    // Checking the protocol address.
    if (ntoh16(arp->hdr.pro) != ARP_PRO_IP || arp->hdr.pln != IP_ADDR_LEN) {
        errorf("unsupported protocol address");
        return;
    }

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);

    memcpy(&spa, arp->spa, sizeof(spa));
    memcpy(&tpa, arp->tpa, sizeof(tpa));

    // Update for all received ARP messages, regardless of destination, but do not add new entry to the cache.
    mutex_lock(&mutex);
    if (arp_cache_update(spa, arp->sha)) {
        // TODO: ARP request.
        merge = 1;
    }
    mutex_unlock(&mutex);

    // Trasnmit an ARP reply in response to an ARP request.
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        if (!merge) {
            mutex_lock(&mutex);
            arp_cache_insert(spa, arp->sha);
            mutex_unlock(&mutex);
        }
        if (ntoh16(arp->hdr.op) == ARP_OP_REQUEST) {
            arp_reply(iface, arp->sha, spa, arp->sha);
        }
    }
}

// Resolve the hardware address using the protocol address and store it in `ha`.
int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha) {
    struct arp_cache *cache;
    // For debug log.
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    if (iface->family != NET_IFACE_FAMILY_IP) {
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }

    mutex_lock(&mutex);
    cache = arp_cache_select(pa);
    if (!cache) {
        debugf("cache not found, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));
        mutex_unlock(&mutex);

        arp_request(iface, pa);

        return ARP_RESOLVE_INCOMPLETE;
    }

    // Retransmit ARP request if the entry remains INCOMPLETE, considering the possibility of packet loss.
    if (cache->state == ARP_CACHE_STATE_INCOMPLETE) {
        mutex_unlock(&mutex);

        arp_request(iface, pa);

        return ARP_RESOLVE_INCOMPLETE;
    }

    memcpy(ha, cache->ha, ETHER_ADDR_LEN);
    mutex_unlock(&mutex);

    debugf("resolved, pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));

    return ARP_RESOLVE_FOUND;
}

int arp_init(void) {
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    return 0;
}
