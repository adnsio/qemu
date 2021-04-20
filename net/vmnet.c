/**
 * vmnet network backend
 *
 * Copyright (c) 2021 Alessio Dionisi <hello@adns.io>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "net/net.h"
#include "qapi/qapi-types-net.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/osdep.h"

#include <vmnet/vmnet.h>

typedef struct NetVmnetState {
    NetClientState nc;
    interface_ref interface;
    bool started;
    bool receive_packets;
} NetVmnetState;

int net_init_vmnet(const Netdev *netdev, const char *name, NetClientState *peer,
                   Error **errp);

static const char *_vmnet_status_repr(vmnet_return_t status) {
    switch (status) {
    case VMNET_SUCCESS:
        return "success";
    case VMNET_FAILURE:
        return "generic failure";
    case VMNET_MEM_FAILURE:
        return "out of memory";
    case VMNET_INVALID_ARGUMENT:
        return "invalid argument";
    case VMNET_SETUP_INCOMPLETE:
        return "setup is incomplete";
    case VMNET_INVALID_ACCESS:
        return "insufficient permissions";
    case VMNET_PACKET_TOO_BIG:
        return "packet size exceeds MTU";
    case VMNET_BUFFER_EXHAUSTED:
        return "kernel buffers temporarily exhausted";
    case VMNET_TOO_MANY_PACKETS:
        return "number of packets exceeds system limit";
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 110000
    case VMNET_SHARING_SERVICE_BUSY:
        return "sharing service busy";
#endif
    default:
        return "unknown status code";
    }
}

static bool vmnet_can_receive(NetClientState *nc) {
    NetVmnetState *s = DO_UPCAST(NetVmnetState, nc, nc);
    return s->started;
}

static ssize_t vmnet_receive_iov(NetClientState *nc, const struct iovec *iovs,
                                 int iovcnt) {
    NetVmnetState *s = DO_UPCAST(NetVmnetState, nc, nc);

    /* Combine the provided iovs into a single vmnet packet */
    struct vmpktdesc *packet = g_new0(struct vmpktdesc, 1);
    packet->vm_pkt_iov = g_new0(struct iovec, iovcnt);
    memcpy(packet->vm_pkt_iov, iovs, sizeof(struct iovec) * iovcnt);
    packet->vm_pkt_iovcnt = iovcnt;
    packet->vm_flags = 0;

    /* Figure out the packet size by iterating the iov's */
    for (int i = 0; i < iovcnt; i++) {
        const struct iovec *iov = iovs + i;
        packet->vm_pkt_size += iov->iov_len;
    }

    /* Finally, write the packet to the vmnet interface */
    int packet_count = 1;
    vmnet_return_t result = vmnet_write(s->interface, packet, &packet_count);
    if (result != VMNET_SUCCESS || packet_count != 1) {
        error_printf("failed to send packet to host: %s\n",
                     _vmnet_status_repr(result));
    }
    ssize_t wrote_bytes = packet->vm_pkt_size;
    g_free(packet->vm_pkt_iov);
    g_free(packet);
    return wrote_bytes;
}

static void vmnet_send_completed(NetClientState *nc, ssize_t len) {
    NetVmnetState *s = DO_UPCAST(NetVmnetState, nc, nc);
    /* Ready to receive more packets! */
    s->receive_packets = true;
}

static NetClientInfo net_vmnet_info = {
    .type = NET_CLIENT_DRIVER_VMNET,
    .size = sizeof(NetVmnetState),
    .receive_iov = vmnet_receive_iov,
    .can_receive = vmnet_can_receive,
};

int net_init_vmnet(const Netdev *netdev, const char *name, NetClientState *peer,
                   Error **errp) {
    assert(netdev->type == NET_CLIENT_DRIVER_VMNET);

    operating_modes_t mode = VMNET_SHARED_MODE;

    xpc_object_t iface_desc = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(iface_desc, vmnet_operation_mode_key, mode);

    NetClientState *nc =
        qemu_new_net_client(&net_vmnet_info, peer, "vmnet", name);
    NetVmnetState *s = DO_UPCAST(NetVmnetState, nc, nc);

    dispatch_queue_t vmnet_dispatch_queue =
        dispatch_queue_create("vmnet", DISPATCH_QUEUE_SERIAL);

    __block vmnet_return_t vmnet_start_status = 0;
    __block uint64_t vmnet_iface_mtu = 0;
    __block uint64_t vmnet_max_packet_size = 0;
    __block const char *mac_address = NULL;
    /* These are only provided in VMNET_HOST_MODE and VMNET_SHARED_MODE */
    bool vmnet_provides_dhcp_info =
        (mode == VMNET_HOST_MODE || mode == VMNET_SHARED_MODE);
    __block const uint8_t *uuid = NULL;
    __block const char *subnet_mask = NULL;
    __block const char *dhcp_start = NULL;
    __block const char *dhcp_end = NULL;

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    interface_ref interface = vmnet_start_interface(
        iface_desc, vmnet_dispatch_queue,
        ^(vmnet_return_t status, xpc_object_t _Nullable interface_param) {
          vmnet_start_status = status;

          if (vmnet_start_status != VMNET_SUCCESS || !interface_param) {
              dispatch_semaphore_signal(semaphore);
              return;
          }

          /*
           * Read the configuration that vmnet provided us.
           * The provided dictionary is owned by XPC and may be freed
           * shortly after this block's execution.
           * So, copy data buffers now.
           */
          vmnet_iface_mtu =
              xpc_dictionary_get_uint64(interface_param, vmnet_mtu_key);
          vmnet_max_packet_size = xpc_dictionary_get_uint64(
              interface_param, vmnet_max_packet_size_key);
          mac_address = strdup(xpc_dictionary_get_string(
              interface_param, vmnet_mac_address_key));

          uuid =
              xpc_dictionary_get_uuid(interface_param, vmnet_interface_id_key);

          /* If we're in a mode that provides DHCP info, read it out now */
          if (vmnet_provides_dhcp_info) {
              dhcp_start = strdup(xpc_dictionary_get_string(
                  interface_param, vmnet_start_address_key));
              dhcp_end = strdup(xpc_dictionary_get_string(
                  interface_param, vmnet_end_address_key));
              subnet_mask = strdup(xpc_dictionary_get_string(
                  interface_param, vmnet_subnet_mask_key));
          }

          dispatch_semaphore_signal(semaphore);
        });

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (vmnet_start_status != VMNET_SUCCESS || !interface) {
        error_printf("failed to start interface: %s\n",
                     _vmnet_status_repr(vmnet_start_status));
        if (vmnet_start_status == VMNET_FAILURE) {
            error_printf("note: vmnet requires running with root access\n");
        }
        return -1;
    }

    info_report("mac address: %s, mtu: %llu, max packet size: %llu",
                mac_address, vmnet_iface_mtu, vmnet_max_packet_size);

    if (vmnet_provides_dhcp_info) {
        info_report("dhcp range: %s - %s, dhcp mask: %s", dhcp_start, dhcp_end,
                    subnet_mask);
    }

    s->interface = interface;

    vmnet_return_t event_cb_stat = vmnet_interface_set_event_callback(
        interface, VMNET_INTERFACE_PACKETS_AVAILABLE, vmnet_dispatch_queue,
        ^(interface_event_t event_mask, xpc_object_t _Nonnull event) {
          if (event_mask != VMNET_INTERFACE_PACKETS_AVAILABLE) {
              error_printf("unknown vmnet interface event 0x%08x\n",
                           event_mask);
              return;
          }

          /* If we're unable to handle more packets now, drop this packet */
          if (!s->receive_packets) {
              return;
          }

          /*
           * TODO(Phillip Tennen <phillip@axleos.com>): There may be more than
           * one packet available.
           * As an optimization, we could read
           * vmnet_estimated_packets_available_key packets now.
           */
          char *packet_buf = g_malloc0(vmnet_max_packet_size);
          struct iovec *iov = g_new0(struct iovec, 1);
          iov->iov_base = packet_buf;
          iov->iov_len = vmnet_max_packet_size;

          int pktcnt = 1;
          struct vmpktdesc *v = g_new0(struct vmpktdesc, pktcnt);
          v->vm_pkt_size = vmnet_max_packet_size;
          v->vm_pkt_iov = iov;
          v->vm_pkt_iovcnt = 1;
          v->vm_flags = 0;

          vmnet_return_t result = vmnet_read(interface, v, &pktcnt);
          if (result != VMNET_SUCCESS) {
              error_printf("failed to read packet from host: %s\n",
                           _vmnet_status_repr(result));
          }

          /* Ensure we read exactly one packet */
          assert(pktcnt == 1);

          /* Dispatch this block to a global queue instead of the main queue,
           * which is only created when the program has a Cocoa event loop.
           * If QEMU is started with -nographic, no Cocoa event loop will be
           * created and thus the main queue will be unavailable.
           */
          dispatch_async(
              dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                qemu_mutex_lock_iothread();

                /*
                 * Deliver the packet to the guest
                 * If the delivery succeeded synchronously, this returns the
                 * length of the sent packet.
                 */
                if (qemu_send_packet_async(nc, iov->iov_base, v->vm_pkt_size,
                                           vmnet_send_completed) == 0) {
                    s->receive_packets = false;
                }

                /*
                 * It's safe to free the packet buffers.
                 * Even if delivery needs to wait, qemu_net_queue_append copies
                 * the packet buffer.
                 */
                g_free(v);
                g_free(iov);
                g_free(packet_buf);

                qemu_mutex_unlock_iothread();
              });
        });

    /* Did we manage to set an event callback? */
    if (event_cb_stat != VMNET_SUCCESS) {
        error_printf("failed to set up a callback to receive packets: %s\n",
                     _vmnet_status_repr(vmnet_start_status));
        exit(1);
    }

    /* We're now ready to receive packets */
    s->receive_packets = true;
    s->started = true;

    /* Include DHCP info if we're in a relevant mode */
    if (vmnet_provides_dhcp_info) {
        snprintf(nc->info_str, sizeof(nc->info_str),
                 "dhcp_start=%s,dhcp_end=%s,mask=%s", dhcp_start, dhcp_end,
                 subnet_mask);
    } else {
        snprintf(nc->info_str, sizeof(nc->info_str), "mac=%s", mac_address);
    }

    return 0;
}
