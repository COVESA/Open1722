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
#include "avtp/acf/Can.h"
#include "avtp/CommonHeader.h"
#include "acf-can-common.h"

#define ARGPARSE_CAN_FD_OPTION      500
#define ARGPARSE_CAN_IF_OPTION      501
#define ARGPARSE_TALKER_ID_OPTION      502
#define ARGPARSE_LISTENER_ID_OPTION     503
#define TALKER_STREAM_ID            0xAABBCCDDEEFF0001
#define LISTENER_STREAM_ID  	    0xAABBCCDDEEFF0001

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t ip_addr[sizeof(struct in_addr)];
static int priority = -1;
static uint8_t use_tscf = 0;
static uint8_t use_udp = 0;
static uint32_t udp_listen_port = 17220;
static uint32_t udp_send_port = 17220;
static Avtp_CanVariant_t can_variant = AVTP_CAN_CLASSIC;
static uint8_t num_acf_msgs = 1;
static char can_ifname[IFNAMSIZ];
static uint64_t talker_stream_id = TALKER_STREAM_ID;
static uint64_t listener_stream_id = LISTENER_STREAM_ID;
static char ip_addr_str[100];

int eth_socket, can_socket;
struct sockaddr* dest_addr;

static char doc[] =
        "\nacf-can-bridge -- a program for bridging a CAN interface with an Ethernet interface using IEEE 1722.\
        \vEXAMPLES\n\
        acf-can-bridge -i eth0 -d aa:bb:cc:dd:ee:ff --canif can1\n\
        \t(Bridge eth0 with can1 using Open1722 using Ethernet)\n\
        acf-can-bridge --canif can1 -u -p 17220\n\
        \t(Bridge eth0 with can1 using Open1722 over UDP)";

static struct argp_option options[] = {
    {"tscf", 't', 0, 0, "Use TSCF"},
    {"udp", 'u', 0, 0, "Use UDP" },
    {"fd", ARGPARSE_CAN_FD_OPTION, 0, 0, "Use CAN-FD"},
    {"count", 'c', "COUNT", 0, "Set count of CAN messages per Ethernet frame"},
    {"canif", ARGPARSE_CAN_IF_OPTION, "CAN_IF", 0, "CAN interface"},
    {"ifname", 'i', "IFNAME", 0, "Network interface (If Ethernet)"},
    {"dst-addr", 'd', "MACADDR", 0, "Stream destination MAC address (If Ethernet)"},
    {"dst-nw-addr", 'n', "NW_ADDR", 0, "Stream destination network address and port (If UDP)"},
    {"udp-port", 'p', "UDP_PORT", 0, "UDP Port to listen on (if UDP)"},
    {"listener-stream-id", ARGPARSE_LISTENER_ID_OPTION, "STREAM_ID", 0, "Stream ID for listener stream"},
    {"talker-stream-id", ARGPARSE_TALKER_ID_OPTION, "STREAM_ID", 0, "Stream ID for talker stream"},
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
    case 'c':
        num_acf_msgs = atoi(arg);
        if ((num_acf_msgs < 1) || (num_acf_msgs > MAX_CAN_FRAMES_IN_ACF)) {
            fprintf(stderr, "Invalid number of CAN messages in one AVTP frame.\n");
            exit(EXIT_FAILURE);
        }
        break;
    case ARGPARSE_CAN_FD_OPTION:
        can_variant = AVTP_CAN_FD;
        break;
    case ARGPARSE_CAN_IF_OPTION:
        strncpy(can_ifname, arg, sizeof(can_ifname) - 1);
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
        listener_stream_id = atoi(arg);
        break;
    case ARGPARSE_TALKER_ID_OPTION:
        talker_stream_id = atoi(arg);
        break;
    }

    return 0;
}

static struct argp argp = { options, parser, NULL, doc};

void* can_to_avtp_runnable(void* args) {

    uint8_t cf_seq_num = 0;
    uint32_t udp_seq_num = 0;

    uint8_t pdu[MAX_ETH_PDU_SIZE];
    uint16_t pdu_length = 0;
    frame_t can_frames[num_acf_msgs];
    int res;

    // Start an infinite loop to keep converting CAN frames to AVTP frames
    for(;;) {

        // Read acf_num_msgs number of CAN frames from the CAN socket
        int i = 0;
        while (i < num_acf_msgs) {
            // Get payload -- will 'spin' here until we get the requested number
            //                of CAN frames.
            if(can_variant == AVTP_CAN_FD){
                res = read(can_socket, &(can_frames[i].fd), sizeof(struct canfd_frame));
            } else {
                res = read(can_socket, &(can_frames[i].cc), sizeof(struct can_frame));
            }
            if (!res) {
                perror("Error reading CAN frames");
                continue;
            }
            i++;
        }

        // Pack all the read frames into an AVTP frame
        pdu_length = can_to_avtp(can_frames, can_variant, pdu, use_udp, use_tscf,
                                    talker_stream_id, num_acf_msgs, cf_seq_num++, udp_seq_num++);

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

void* avtp_to_can_runnable(void* args) {

    uint16_t pdu_length = 0, cf_length = 0;
    int8_t num_can_msgs = 0;
    uint8_t exp_cf_seqnum = 0;
    uint32_t exp_udp_seqnum = 0;
    uint8_t pdu[MAX_ETH_PDU_SIZE];
    frame_t can_frames[MAX_CAN_FRAMES_IN_ACF];

    // Start an infinite loop to keep converting AVTP frames to CAN frames
    for(;;) {

        pdu_length = recv(eth_socket, pdu, MAX_ETH_PDU_SIZE, 0);
        if (pdu_length < 0 || pdu_length > MAX_ETH_PDU_SIZE) {
            perror("Failed to receive data");
            continue;
        }

        num_can_msgs = avtp_to_can(pdu, can_frames, can_variant, use_udp,
                             listener_stream_id, &exp_cf_seqnum, &exp_udp_seqnum);
        if (num_can_msgs <= 0) {
            continue;
        }
        exp_cf_seqnum++;
        exp_udp_seqnum++;

        for (int8_t i = 0; i < num_can_msgs; i++) {
            int res;
            if (can_variant == AVTP_CAN_FD)
                res = write(can_socket, &can_frames[i].fd, sizeof(struct canfd_frame));
            else if (can_variant == AVTP_CAN_CLASSIC)
                res = write(can_socket, &can_frames[i].cc, sizeof(struct can_frame));

            if(res < 0)
            {
                perror("Failed to write to CAN bus");
            }
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
    printf("acf-can-bridge configuration:\n");
    if(use_tscf)
        printf("\tUsing TSCF\n");
    else
        printf("\tUsing NTSCF\n");
    if(can_variant == AVTP_CAN_CLASSIC)
        printf("\tUsing Classic CAN interface: %s\n", can_ifname);
    else if(can_variant == AVTP_CAN_FD)
        printf("\tUsing CAN FD interface: %s\n", can_ifname);
    if(use_udp) {
        printf("\tUsing UDP\n");
        printf("\tDestination IP: %s, Send port: %d, listening port: %d\n", ip_addr_str, udp_send_port, udp_listen_port);
    } else {
        printf("\tUsing Ethernet\n");
        printf("\tNetwork Interface: %s\n", ifname);
        printf("\tDestination MAC Address: %x:%x:%x:%x:%x:%x\n", macaddr[0], macaddr[1], macaddr[2],
                                                        macaddr[3], macaddr[4], macaddr[5]);
    }
    printf("\tListener Stream ID: %lx, Talker Stream ID: %lx\n", listener_stream_id, talker_stream_id);
    printf("\tNumber of ACF messages per AVTP frame in talker stream: %d\n", num_acf_msgs);

    // Create an appropriate sockets: UDP or Ethernet raw
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

    // Open a CAN socket for reading frames
    can_socket = setup_can_socket(can_ifname, can_variant);
    if (can_socket < 0) return 1;

    pthread_t can_to_avtp_thread, avtp_to_can_thread;

    // Start the threads for the bridge
    pthread_create(&can_to_avtp_thread, NULL, can_to_avtp_runnable, NULL);
    pthread_create(&avtp_to_can_thread, NULL, avtp_to_can_runnable, NULL);

    // Wait for the threads to complete
    pthread_join(can_to_avtp_thread, NULL);
    pthread_join(avtp_to_can_thread, NULL);

    return 1;
}