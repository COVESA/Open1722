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

#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/can/raw.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "common/common.h"
#include "acf-can-common.h"

#define STREAM_ID                   0xAABBCCDDEEFF0001
#define CAN_PAYLOAD_MAX_SIZE        16*4
#define ARGPARSE_CAN_FD_OPTION      500
#define ARGPARSE_CAN_IF_OPTION      501
#define ARGPARSE_TALKER_ID_OPTION      502

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t ip_addr[sizeof(struct in_addr)];
static uint32_t udp_port=17220;
static int priority = -1;
static uint8_t use_tscf = 0;
static uint8_t use_udp = 0;
static Avtp_CanVariant_t can_variant = AVTP_CAN_CLASSIC;
static uint8_t num_acf_msgs = 1;
static char can_ifname[IFNAMSIZ];
static uint64_t talker_stream_id = STREAM_ID;
static char ip_addr_str[100];

static char doc[] =
        "\nacf-can-talker -- a program to send CAN messages to a remote CAN bus over Ethernet using Open1722.\
         \vEXAMPLES\n\
         acf-can-talker -i eth0 -d aa:bb:cc:ee:dd:ff --canif vcan0\n\
         \t(tunnel transactions from CAN vcan0 over Ethernet eth0)\n\n\
         acf-can-talker -u --dst-nw-addr 10.0.0.2:17220 --canif vcan1\n\
         \t(tunnel transactions from vcan1 interface using UDP)";

static struct argp_option options[] = {
    {"tscf", 't', 0, 0, "Use TSCF (Default: NTSCF)"},
    {"udp", 'u', 0, 0, "Use UDP (Default: Ethernet)" },
    {"fd", ARGPARSE_CAN_FD_OPTION, 0, 0, "Use CAN-FD"},
    {"count", 'c', "COUNT", 0, "Set count of CAN messages per Ethernet frame"},
    {"canif", ARGPARSE_CAN_IF_OPTION, "CAN_IF", 0, "CAN interface"},
    {"ifname", 'i', "IFNAME", 0, "Network interface (If Ethernet)"},
    {"dst-addr", 'd', "MACADDR", 0, "Stream destination MAC address (If Ethernet)"},
    {"dst-nw-addr", 'n', "NW_ADDR", 0, "Stream destination network address and port (If UDP)"},
    {"stream-id", ARGPARSE_TALKER_ID_OPTION, "STREAM_ID", 0, "Stream ID for talker stream"},
    { 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;

    switch (key) {
    case 't':
        use_tscf = 1;
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
        res = sscanf(arg, "%[^:]:%d", ip_addr_str, &udp_port);
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
    case ARGPARSE_TALKER_ID_OPTION:
        talker_stream_id = atoi(arg);
        break;
    }

    return 0;
}

static struct argp argp = { options, parser, NULL, doc};

int main(int argc, char *argv[])
{
    int fd, res, can_socket=0;
    struct sockaddr_ll sk_ll_addr;
    struct sockaddr_in sk_udp_addr;
    struct sockaddr* dest_addr;
    uint8_t cf_seq_num = 0;
    uint32_t udp_seq_num = 0;

    uint8_t pdu[MAX_ETH_PDU_SIZE];
    uint16_t pdu_length = 0;
    frame_t can_frames[num_acf_msgs];

    argp_parse(&argp, argc, argv, 0, NULL, NULL);
    printf("acf-talker-configuration:\n");
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
        printf("\tDestination IP: %s, Send port: %d\n", ip_addr_str, udp_port);
    } else {
        printf("\tUsing Ethernet\n");
        printf("\tNetwork Interface: %s\n", ifname);
        printf("\tDestination MAC Address: %x:%x:%x:%x:%x:%x\n", macaddr[0], macaddr[1], macaddr[2],
                                                        macaddr[3], macaddr[4], macaddr[5]);
    }
    printf("\tTalker Stream ID: %lx\n", talker_stream_id);
    printf("\tNumber of ACF messages per AVTP frame in talker stream: %d\n", num_acf_msgs);

    // Create an appropriate talker socket: UDP or Ethernet raw
    // Setup the socket for sending to the destination
    if (use_udp) {
        fd = create_talker_socket_udp(priority);
        if (fd < 0) return fd;

        res = setup_udp_socket_address((struct in_addr*) ip_addr,
                                       udp_port, &sk_udp_addr);
        dest_addr = (struct sockaddr*) &sk_udp_addr;
    } else {
        fd = create_talker_socket(priority);
        if (fd < 0) return fd;
        res = setup_socket_address(fd, ifname, macaddr,
                                   ETH_P_TSN, &sk_ll_addr);
        dest_addr = (struct sockaddr*) &sk_ll_addr;
    }
    if (res < 0) goto err;

    // Open a CAN socket for reading frames
    can_socket = setup_can_socket(can_ifname, can_variant);
    if (can_socket < 0) goto err;

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
            res = sendto(fd, pdu, pdu_length, 0,
                    (struct sockaddr *) dest_addr, sizeof(struct sockaddr_in));
        } else {
            res = sendto(fd, pdu, pdu_length, 0,
                         (struct sockaddr *) dest_addr, sizeof(struct sockaddr_ll));
        }
        if (res < 0) {
            perror("Failed to send data");
        }
    }

err:
    close(fd);
    return 1;

}
