#include "arp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ether.h"
#include "ip.h"
#include "net.h"
#include "util.h"

// see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt
#define ARP_HRD_ETHER 0x0001
// NOTE: use same value as the Ethernet types.
#define ARP_PRO_IP ETHER_TYPE_IP

// Operation codes.
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

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

    // Trasnmit an ARP reply in response to an ARP request.
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        if (ntoh16(arp->hdr.op) == ARP_OP_REQUEST) {
            arp_reply(iface, arp->sha, spa, arp->sha);
        }
    }
}

int arp_init(void) {
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    return 0;
}
