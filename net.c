#include "net.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "platform.h"
#include "util.h"

// Linked list of network devices.
// NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex.
static struct net_device *devices;

struct net_device *net_device_alloc(void) {
    struct net_device *dev;

    dev = memory_alloc(sizeof(*dev));
    if (!dev) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    return dev;
}

// Add the `dev`, which is allocated and set except for the `index` and `name` , to the list of network devices.
// NOTE: must not be call after net_run()
int net_device_register(struct net_device *dev) {
    static unsigned int index = 0;

    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);

    dev->next = devices;
    devices = dev;
    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);

    return 0;
}

static int net_device_open(struct net_device *dev) {
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }

    if (dev->ops->open) {
        if (dev->ops->open(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));

    return 0;
}

static int net_device_close(struct net_device *dev) {
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }

    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));

    return 0;
}

// Transmit data using the device driver's transmit function.
int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst) {
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    // Split data into chunks that are less than or equal to MTU in the upper layer.
    if (len > dev->mtu) {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }

    return 0;
}

// Pass the received data to the upper protocol stack from the device.
// dev1 -> driver1 -
//                  |-> net_input_handler() -> protocol handler
// dev2 -> driver2 -
int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev) {
    // nop

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    return 0;
}

int net_run(void) {
    struct net_device *dev;

    debugf("open all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_open(dev);
    }
    debugf("running...");

    return 0;
}

void net_shutdown(void) {
    struct net_device *dev;

    debugf("close all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_close(dev);
    }
    debugf("shutting down");
}

int net_init(void) {
    // nop

    infof("initialized");

    return 0;
}
