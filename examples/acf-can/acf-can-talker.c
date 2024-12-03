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
#include <time.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

#include "common/common.h"
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "avtp/CommonHeader.h"
#include "acf-can-common.h"

#define MAX_PDU_SIZE                1500
#define STREAM_ID                   0xAABBCCDDEEFF0001
#define CAN_PAYLOAD_MAX_SIZE        16*4
#define ARGPARSE_CAN_FD_OPTION      500
#define ARGPARSE_CAN_IF_OPTION      501

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t ip_addr[sizeof(struct in_addr)];
static uint32_t udp_port=17220;
static int priority = -1;
static uint8_t seq_num = 0;
static uint32_t udp_seq_num = 0;
static uint8_t use_tscf;
static uint8_t use_udp;
static Avtp_CanVariant_t can_variant = AVTP_CAN_CLASSIC;
static uint8_t num_acf_msgs = 1;
static char can_ifname[IFNAMSIZ];

static char doc[] =
        "\nacf-can-talker -- a program designed to send CAN messages to a remote CAN bus over Ethernet using Open1722.\
         \vEXAMPLES\n\
         acf-can-talker -i eth0 -d aa:bb:cc:ee:dd:ff --canif vcan0\n\
         \t(tunnel transactions from CAN vcan0 over Ethernet eth0)\n\n\
         acf-can-talker -u --dst-nw-addr 10.0.0.2:17220 --canif vcan1\n\
         \t(tunnel transactions from vcan1 interface using UDP)";

static struct argp_option options[] = {
    {"tscf", 't', 0, 0, "Use TSCF"},
    {"udp", 'u', 0, 0, "Use UDP" },
    {"fd", ARGPARSE_CAN_FD_OPTION, 0, 0, "Use CAN-FD"},
    {"count", 'c', "COUNT", 0, "Set count of CAN messages per Ethernet frame"},
    {"canif", ARGPARSE_CAN_IF_OPTION, "CAN_IF", 0, "CAN interface"},
    {"ifname", 'i', "IFNAME", 0, "Network interface (If Ethernet)"},
    {"dst-addr", 'd', "MACADDR", 0, "Stream destination MAC address (If Ethernet)"},
    {"dst-nw-addr", 'n', "NW_ADDR", 0, "Stream destination network address and port (If UDP)"},
    { 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;
    char ip_addr_str[100];

    switch (key) {
    case 't':
        use_tscf = 1;
        break;
    case 'u':
        use_udp = 1;
        break;
    case 'c':
        num_acf_msgs = atoi(arg);
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
    }

    return 0;
}

static struct argp argp = { options, parser, NULL, doc};

static int init_cf_pdu(uint8_t* pdu)
{
    int res;
    if (use_tscf) {
        Avtp_Tscf_t* tscf_pdu = (Avtp_Tscf_t*) pdu;
        memset(tscf_pdu, 0, AVTP_TSCF_HEADER_LEN);
        Avtp_Tscf_Init(tscf_pdu);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_TU, 0U);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM, seq_num++);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_STREAM_ID, STREAM_ID);
        res = AVTP_TSCF_HEADER_LEN;
    } else {
        Avtp_Ntscf_t* ntscf_pdu = (Avtp_Ntscf_t*) pdu;
        memset(ntscf_pdu, 0, AVTP_NTSCF_HEADER_LEN);
        Avtp_Ntscf_Init(ntscf_pdu);
        Avtp_Ntscf_SetField(ntscf_pdu, AVTP_NTSCF_FIELD_SEQUENCE_NUM, seq_num++);
        Avtp_Ntscf_SetField(ntscf_pdu, AVTP_NTSCF_FIELD_STREAM_ID, STREAM_ID);
        res = AVTP_NTSCF_HEADER_LEN;
    }
    return res;
}

static int update_cf_length(uint8_t* cf_pdu, uint64_t length)
{
    if (use_tscf) {
        uint64_t payloadLen = length - AVTP_TSCF_HEADER_LEN;
        Avtp_Tscf_SetField((Avtp_Tscf_t*)cf_pdu, AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, payloadLen);
    } else {
        uint64_t payloadLen = length - AVTP_NTSCF_HEADER_LEN;
        Avtp_Ntscf_SetField((Avtp_Ntscf_t*)cf_pdu, AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH, payloadLen);
    }
    return 0;
}

static int prepare_acf_packet(uint8_t* acf_pdu,
                              frame_t frame) {

    int processedBytes;
    struct timespec now;
    Avtp_Can_t* pdu = (Avtp_Can_t*) acf_pdu;
    canid_t can_id;

    // Clear bits
    memset(pdu, 0, AVTP_CAN_HEADER_LEN);

    // Prepare ACF PDU for CAN
    Avtp_Can_Init(pdu);
    clock_gettime(CLOCK_REALTIME, &now);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_MESSAGE_TIMESTAMP,
                      (uint64_t)now.tv_nsec + (uint64_t)(now.tv_sec * 1e9));
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_MTV, 1U);

    // Set required CAN Flags
    can_id = (can_variant == AVTP_CAN_FD) ? frame.fd.can_id : frame.cc.can_id;
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_RTR, can_id & CAN_RTR_FLAG);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_EFF, can_id & CAN_EFF_FLAG);

    if (can_variant == AVTP_CAN_FD) {
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_BRS, frame.fd.flags & CANFD_BRS);
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_FDF, frame.fd.flags & CANFD_FDF);
        Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_ESI, frame.fd.flags & CANFD_ESI);
    }

    // Copy payload to ACF CAN PDU
    if(can_variant == AVTP_CAN_FD)
        Avtp_Can_CreateAcfMessage(pdu, frame.fd.can_id & CAN_EFF_MASK, frame.fd.data,
                                         frame.fd.len, can_variant);
    else
        Avtp_Can_CreateAcfMessage(pdu, frame.cc.can_id & CAN_EFF_MASK, frame.cc.data,
                                         frame.cc.len, can_variant);

    return Avtp_Can_GetAcfMsgLength(pdu)*4;
}

int main(int argc, char *argv[])
{

    int fd, res, can_socket=0;
    struct sockaddr_ll sk_ll_addr;
    struct sockaddr_in sk_udp_addr;
    uint8_t pdu[MAX_PDU_SIZE];
    uint16_t pdu_length, cf_length;
    frame_t can_frame;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    // Create an appropriate talker socket: UDP or Ethernet raw
    // Setup the socket for sending to the destination
    if (use_udp) {
        fd = create_talker_socket_udp(priority);
        if (fd < 0) return fd;

        res = setup_udp_socket_address((struct in_addr*) ip_addr,
                                       udp_port, &sk_udp_addr);
    } else {
        fd = create_talker_socket(priority);
        if (fd < 0) return fd;
        res = setup_socket_address(fd, ifname, macaddr,
                                   ETH_P_TSN, &sk_ll_addr);
    }
    if (res < 0) goto err;

    // Open a CAN socket for reading frames
    can_socket = setup_can_socket(can_ifname, can_variant);
    if (!can_socket) goto err;

    // Sending loop
    for(;;) {

        // Pack into control formats
        uint8_t *cf_pdu;
        pdu_length = 0;
        cf_length = 0;

        // Usage of UDP means the PDU needs a
        if (use_udp) {
            Avtp_Udp_t *udp_pdu = (Avtp_Udp_t *) pdu;
            Avtp_Udp_SetField(udp_pdu, AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO,
                              udp_seq_num++);
            pdu_length +=  sizeof(Avtp_Udp_t);
        }

        cf_pdu = pdu + pdu_length;
        res = init_cf_pdu(cf_pdu);
        if (res < 0)
            goto err;
        pdu_length += res;
        cf_length += res;

        int i = 0;
        while (i < num_acf_msgs) {
            // Get payload -- will 'spin' here until we get the requested number
            //                of CAN frames.
            if(can_variant == AVTP_CAN_FD){
                res = read(can_socket, &can_frame.fd, sizeof(struct canfd_frame));
            } else {
                res = read(can_socket, &can_frame.cc, sizeof(struct can_frame));
            }
            if (!res) continue;

            uint8_t* acf_pdu = pdu + pdu_length;
            res = prepare_acf_packet(acf_pdu, can_frame);
            if (res < 0) goto err;
            pdu_length += res;
            cf_length += res;
            i++;
        }

        res = update_cf_length(cf_pdu, cf_length);
        if (res < 0)
            goto err;

        if (use_udp) {
            res = sendto(fd, pdu, pdu_length, 0,
                    (struct sockaddr *) &sk_udp_addr, sizeof(sk_udp_addr));
        } else {
            res = sendto(fd, pdu, pdu_length, 0,
                         (struct sockaddr *) &sk_ll_addr, sizeof(sk_ll_addr));
        }
        if (res < 0) {
            perror("Failed to send data");
            goto err;
        }
    }

err:
    close(fd);
    return 1;

}
