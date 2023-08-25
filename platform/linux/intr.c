#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "net.h"
#include "platform.h"
#include "util.h"

// Struct to hold the necessary information when an interrupt request is received.
// MEMO: IRQ is Interrupt RQuest.
struct irq_entry {
    struct irq_entry *next;
    // Number to identify which device the interrupt is from.
    unsigned int irq;
    // Function called when the interrupt is received.
    int (*handler)(unsigned int irq, void *dev);
    // Flags. Currently only INTR_IRQ_SHARED is supported.
    int flags;
    // For debugging.
    char name[16];
    // Device of the interrupt source.
    // `void *` is for generality.
    void *dev;
};

// List of IRQ entries.
// NOTE: if you want to add/delete the entries after intr_run(), you need to protect these lists with a mutex.
static struct irq_entry *irqs;

static sigset_t sigmask;

// Thread ID of the interrupt thread.
static pthread_t tid;
// Barrier to synchronize the interrupt thread and the main thread.
static pthread_barrier_t barrier;

// Register an interrupt handler and interrupt identification number(IRQ number) as an IRQ.
int intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev) {
    struct irq_entry *entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);

    // Cehck if the IRQ is already registered.
    for (entry = irqs; entry; entry = entry->next) {
        if (entry->irq == irq) {
            // Both IRQs must agree to share the IRQ number.
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
                break;
            } else {
                errorf("irq %u is already registered", irq);
                return -1;
            }
        }
    }

    // Register the IRQ.
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->dev = dev;
    entry->next = irqs;
    irqs = entry;
    sigaddset(&sigmask, irq);
    debugf("registered: irq=%u, name=%s", irq, name);

    return 0;
}

int intr_raise_irq(unsigned int irq) {
    return pthread_kill(tid, (int)irq);
}

// Interrupt thread.
static void *intr_thread(void *arg) {
    int terminate = 0;
    int sig;
    int err;
    struct irq_entry *entry;

    debugf("start...");
    // Wait for `intr_run()` to start.
    pthread_barrier_wait(&barrier);
    while (!terminate) {
        err = sigwait(&sigmask, &sig);
        if (err) {
            errorf("sigwait() %s", strerror(err));
            break;
        }
        switch (sig) {
            case SIGHUP:
                // Stop the interrupt thread.
                terminate = 1;
                break;
            case SIGUSR1:
                // Software interrupt.
                net_softirq_handler();
                break;
            default:
                // Hardware interrupt (emulated by signal).
                // Call the interrupt handler for the IRQ.
                for (entry = irqs; entry; entry = entry->next) {
                    if (entry->irq == (unsigned int)sig) {
                        debugf("irq=%d, name=%s", entry->irq, entry->name);
                        entry->handler(entry->irq, entry->dev);
                    }
                }
                break;
        }
    }
    debugf("terminated");

    return NULL;
}

// Run the interrupt thread.
int intr_run(void) {
    int err;

    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err) {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    // Interrupt thread.
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err) {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    // Wait for `intr_thread()` to start.
    pthread_barrier_wait(&barrier);

    return 0;
}

// Stop the interrupt thread.
void intr_shutdown(void) {
    // Check if an interrupt thread is running.
    if (pthread_equal(tid, pthread_self()) != 0) {
        return;
    }
    pthread_kill(tid, SIGHUP);
    pthread_join(tid, NULL);
}

int intr_init(void) {
    // Run in the main thread.
    tid = pthread_self();
    pthread_barrier_init(&barrier, NULL, 2);  // main thread + interrupt thread
    sigemptyset(&sigmask);
    // SIGHUP emulates interrupts from hardware.
    sigaddset(&sigmask, SIGHUP);
    // Software interrupt.
    sigaddset(&sigmask, SIGUSR1);

    return 0;
}
