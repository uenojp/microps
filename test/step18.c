#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "driver/ether_tap.h"
#include "driver/loopback.h"
#include "icmp.h"
#include "ip.h"
#include "test.h"
#include "udp.h"
#include "util.h"

static volatile sig_atomic_t terminate;

static void on_signal(int signum) {
    terminate = 1;
}

static int setup(void) {
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }

    // loopback device
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }

    // tap device
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }

    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

static void cleanup(void) {
    net_shutdown();
}

int main(int argc, char *argv[]) {
    struct ip_endpoint src, dst;
    size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }

    ip_endpoint_pton("127.0.0.1:10000", &src);
    ip_endpoint_pton("127.0.0.1:7", &dst);

    while (!terminate) {
        if (udp_output(&src, &dst, test_data + offset, sizeof(test_data) - offset) == -1) {
            errorf("udp_output() failure");
            break;
        }
        sleep(1);
    }

    cleanup();

    return 0;
}
