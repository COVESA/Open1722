/*
 * Copyright (c) 2024, COVESA
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of COVESA nor the names of its contributors may be
 *      used to endorse or promote products derived from this software without
 *      specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/can/raw.h>

#include <argp.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "common/common.h"
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/AcfCommon.h"
#include "avtp/acf/Lin.h"
#include "avtp/CommonHeader.h"
#include "acf-lin-common.h"

#define ARGPARSE_LIN_IF_OPTION         500
#define ARGPARSE_TALKER_ID_OPTION      501
#define ARGPARSE_LISTENER_ID_OPTION    502
#define ARGPARSE_LIN_BUS_ID_OPTION     503
#define ARGPARSE_TTY_OPTION            504
#define ARGPARSE_BAUDRATE_OPTION       505
#define TALKER_STREAM_ID               0xAABBCCDDEEFF0001
#define LISTENER_STREAM_ID             0xAABBCCDDEEFF0001
#define DEFAULT_LIN_BUS_ID             0
#define DEFAULT_LIN_BAUDRATE           19200

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t ip_addr[sizeof(struct in_addr)];
static int priority = -1;
static uint8_t use_tscf = 0;
static uint8_t use_udp = 0;
static uint32_t udp_listen_port = 17220;
static uint32_t udp_send_port = 17220;
static char lin_ifname[IFNAMSIZ];
static uint8_t lin_bus_id = DEFAULT_LIN_BUS_ID;
static uint64_t talker_stream_id = TALKER_STREAM_ID;
static uint64_t listener_stream_id = LISTENER_STREAM_ID;
static char ip_addr_str[100];
static char tty_device[256];
static uint32_t baudrate = DEFAULT_LIN_BAUDRATE;

int eth_socket, lin_socket;
struct sockaddr* dest_addr;

static char doc[] =
        "\nacf-lin-bridge -- a program for bridging a LIN interface with an Ethernet interface using IEEE 1722.\
        \vEXAMPLES\n\
        acf-lin-bridge -i eth0 -d aa:bb:cc:dd:ee:ff -l sllin0\n\
        \t(Bridge eth0 with sllin0 using Open1722 over Ethernet)\n\
        acf-lin-bridge -l sllin0 -u -p 17220\n\
        \t(Bridge eth0 with sllin0 using Open1722 over UDP)\n\
        acf-lin-bridge -l sllin0 -i eth0 -d aa:bb:cc:dd:ee:ff --tty /dev/ttyS0\n\
        \t(Set up sllin on /dev/ttyS0 first, then bridge)";

static struct argp_option options[] = {
    {"tscf", 't', 0, 0, "Use TSCF"},
    {"udp", 'u', 0, 0, "Use UDP" },
    {"linif", ARGPARSE_LIN_IF_OPTION, "LIN_IF", 0, "LIN (sllin) interface"},
    {"lin-bus-id", ARGPARSE_LIN_BUS_ID_OPTION, "BUS_ID", 0, "LIN bus ID for ACF field (0-31, default: 0)"},
    {"ifname", 'i', "IFNAME", 0, "Network interface (If Ethernet)"},
    {"dst-addr", 'd', "MACADDR", 0, "Stream destination MAC address (If Ethernet)"},
    {"dst-nw-addr", 'n', "NW_ADDR", 0, "Stream destination network address and port (If UDP)"},
    {"udp-port", 'p', "UDP_PORT", 0, "UDP Port to listen on (if UDP)"},
    {"listener-stream-id", ARGPARSE_LISTENER_ID_OPTION, "STREAM_ID", 0, "Stream ID for listener stream"},
    {"talker-stream-id", ARGPARSE_TALKER_ID_OPTION, "STREAM_ID", 0, "Stream ID for talker stream"},
    {"tty", ARGPARSE_TTY_OPTION, "TTY", 0, "Optional TTY device for sllin setup (e.g. /dev/ttyS0)"},
    {"baudrate", ARGPARSE_BAUDRATE_OPTION, "BAUDRATE", 0, "Baudrate for sllin setup (default: 19200)"},
    { 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;

    switch (key) {
    case 't':
        use_tscf = 1;
        break;
    case 'p':
        udp_listen_port = atoi(arg);
        break;
    case 'u':
        use_udp = 1;
        break;
    case ARGPARSE_LIN_IF_OPTION:
        strncpy(lin_ifname, arg, sizeof(lin_ifname) - 1);
        break;
    case ARGPARSE_LIN_BUS_ID_OPTION:
        lin_bus_id = (uint8_t) atoi(arg);
        if (lin_bus_id > 31) {
            fprintf(stderr, "Invalid LIN bus ID (must be 0-31).\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'i':
        strncpy(ifname, arg, sizeof(ifname) - 1);
        break;
    case 'd':
        res = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &macaddr[0], &macaddr[1], &macaddr[2],
                &macaddr[3], &macaddr[4], &macaddr[5]);
        if (res != 6) {
            fprintf(stderr, "Invalid MAC address\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'n':
        res = sscanf(arg, "%[^:]:%d", ip_addr_str, &udp_send_port);
        if (!res) {
            fprintf(stderr, "Invalid IP address or port\n");
            exit(EXIT_FAILURE);
        }
        res = inet_pton(AF_INET, ip_addr_str, ip_addr);
        if (!res) {
            fprintf(stderr, "Invalid IP address\n");
            exit(EXIT_FAILURE);
        }
        break;
    case ARGPARSE_LISTENER_ID_OPTION:
        res = sscanf(arg, "%lx", &listener_stream_id);
        if (res != 1) {
            fprintf(stderr, "Invalid listener stream id\n");
            exit(EXIT_FAILURE);
        }
        break;
    case ARGPARSE_TALKER_ID_OPTION:
        res = sscanf(arg, "%lx", &talker_stream_id);
        if (res != 1) {
            fprintf(stderr, "Invalid talker stream id\n");
            exit(EXIT_FAILURE);
        }
        break;
    case ARGPARSE_TTY_OPTION:
        strncpy(tty_device, arg, sizeof(tty_device) - 1);
        break;
    case ARGPARSE_BAUDRATE_OPTION:
        baudrate = (uint32_t) atoi(arg);
        break;
    }

    return 0;
}

static struct argp argp = { options, parser, NULL, doc};

static int setup_sllin_interface(void)
{
    char cmd[512];

    /* If no TTY device specified, assume sllin is already set up */
    if (tty_device[0] == '\0') {
        return 0;
    }

    printf("Setting up sllin on %s with baudrate %u...\n", tty_device, baudrate);

    /* Try slcan_attach first (common on many systems).
     * The -o flag opens the device, -s sets the baudrate.
     * We use a short timeout to avoid blocking indefinitely. */
    snprintf(cmd, sizeof(cmd), "slcan_attach -o -s%d %s &", baudrate, tty_device);
    int ret = system(cmd);
    if (ret != 0) {
        /* Fall back to ldattach (sllin line discipline is typically 28 for master) */
        fprintf(stderr,
                "slcan_attach not found or failed, trying ldattach instead.\n");
        fprintf(stderr,
                "Note: You may need to load the sllin kernel module first (modprobe sllin).\n");

        snprintf(cmd, sizeof(cmd), "ldattach 28 %s", tty_device);
        ret = system(cmd);
        if (ret != 0) {
            fprintf(stderr,
                    "ldattach also failed. Please set up sllin manually, or check that the sllin kernel module is loaded.\n");
            return -1;
        }
    }

    /* Give the kernel time to create the sllin interface */
    sleep(1);
    printf("sllin setup complete.\n");

    return 0;
}

void* lin_to_avtp_runnable(void* args) {

    uint8_t cf_seq_num = 0;
    uint32_t udp_seq_num = 0;

    uint8_t pdu[MAX_ETH_PDU_SIZE];
    uint16_t pdu_length = 0;
    struct can_frame lin_frame;
    int res;

    // Start an infinite loop to keep converting LIN frames to AVTP frames
    for(;;) {

        // Read a single LIN frame from the sllin socket
        res = read(lin_socket, &lin_frame, sizeof(struct can_frame));
        if (res < 0) {
            perror("Error reading LIN frame");
            continue;
        }

        // Pack the LIN frame into an AVTP frame
        pdu_length = lin_to_avtp(&lin_frame, pdu, use_udp, use_tscf,
                                 talker_stream_id, lin_bus_id,
                                 cf_seq_num++, udp_seq_num++);

        // Send the packed frame out
        if (use_udp) {
            res = sendto(eth_socket, pdu, pdu_length, 0,
                    (struct sockaddr *) dest_addr, sizeof(struct sockaddr_in));
        } else {
            res = sendto(eth_socket, pdu, pdu_length, 0,
                         (struct sockaddr *) dest_addr, sizeof(struct sockaddr_ll));
        }
        if (res < 0) {
            perror("Failed to send data");
        }
    }

    return NULL;
}

void* avtp_to_lin_runnable(void* args) {

    uint16_t pdu_length = 0;
    int num_lin_msgs = 0;
    uint8_t exp_cf_seqnum = 0;
    uint32_t exp_udp_seqnum = 0;
    uint8_t pdu[MAX_ETH_PDU_SIZE];
    struct can_frame lin_frame;

    // Start an infinite loop to keep converting AVTP frames to LIN frames
    for(;;) {

        pdu_length = recv(eth_socket, pdu, MAX_ETH_PDU_SIZE, 0);
        if (pdu_length < 0 || pdu_length > MAX_ETH_PDU_SIZE) {
            perror("Failed to receive data");
            continue;
        }

        num_lin_msgs = avtp_to_lin(pdu, &lin_frame, use_udp,
                             listener_stream_id, &exp_cf_seqnum, &exp_udp_seqnum);
        if (num_lin_msgs <= 0) {
            continue;
        }
        exp_cf_seqnum++;
        exp_udp_seqnum++;

        int res = write(lin_socket, &lin_frame, sizeof(struct can_frame));
        if(res < 0)
        {
            perror("Failed to write to LIN bus");
        }
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    int res;

    struct sockaddr_ll sk_ll_addr;
    struct sockaddr_in sk_udp_addr;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    // Print current configuration
    printf("acf-lin-bridge configuration:\n");
    if(use_tscf)
        printf("\tUsing TSCF\n");
    else
        printf("\tUsing NTSCF\n");
    printf("\tLIN interface: %s\n", lin_ifname);
    printf("\tLIN bus ID: %d\n", lin_bus_id);
    if (tty_device[0] != '\0') {
        printf("\tTTY device: %s\n", tty_device);
        printf("\tBaudrate: %u\n", baudrate);
    }
    if(use_udp) {
        printf("\tUsing UDP\n");
        printf("\tDestination IP: %s, Send port: %d, listening port: %d\n", ip_addr_str, udp_send_port, udp_listen_port);
    } else {
        printf("\tUsing Ethernet\n");
        printf("\tNetwork Interface: %s\n", ifname);
        printf("\tDestination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", macaddr[0], macaddr[1], macaddr[2],
                                                        macaddr[3], macaddr[4], macaddr[5]);
    }
    printf("\tListener Stream ID: 0x%lx, Talker Stream ID: 0x%lx\n", listener_stream_id, talker_stream_id);

    // Optionally set up the sllin interface
    res = setup_sllin_interface();
    if (res < 0) return 1;

    // Create an appropriate socket: UDP or Ethernet raw
    // Setup the socket for sending to the destination
    if (use_udp) {
        eth_socket = create_listener_socket_udp(udp_listen_port);
        if (eth_socket < 0) return 1;

        // Prepare socket for sending to the destination
        res = setup_udp_socket_address((struct in_addr*) ip_addr,
                                       udp_send_port, &sk_udp_addr);
        dest_addr = (struct sockaddr*) &sk_udp_addr;
    } else {
        eth_socket = create_listener_socket(ifname, macaddr, ETH_P_TSN);
        if (eth_socket < 0) return 1;

        // Prepare socket for sending
        res = setup_socket_address(eth_socket, ifname, macaddr,
                                   ETH_P_TSN, &sk_ll_addr);
        dest_addr = (struct sockaddr*) &sk_ll_addr;
    }
    if (res < 0) return 1;

    // Open a LIN socket for reading frames
    lin_socket = setup_lin_socket(lin_ifname);
    if (lin_socket < 0) return 1;

    pthread_t lin_to_avtp_thread, avtp_to_lin_thread;

    // Start the threads for the bridge
    pthread_create(&lin_to_avtp_thread, NULL, lin_to_avtp_runnable, NULL);
    pthread_create(&avtp_to_lin_thread, NULL, avtp_to_lin_runnable, NULL);

    // Wait for the threads to complete
    pthread_join(lin_to_avtp_thread, NULL);
    pthread_join(avtp_to_lin_thread, NULL);

    return 1;
}
