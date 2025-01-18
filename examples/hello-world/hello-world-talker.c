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
#include <linux/can.h>
#include <linux/can/raw.h>
#include <sys/ioctl.h>
#include <time.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "common/common.h"
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/Gpc.h"
#include "avtp/CommonHeader.h"

#define MAX_PDU_SIZE                1500
#define MAX_MSG_SIZE                100
#define STREAM_ID                   0xAABBCCDDEEFF0001
#define ARGPARSE_OPTION_MSG         500
#define GPC_CODE                    256

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static char message_string[MAX_MSG_SIZE] = "Hello World!\0";
static uint8_t ip_addr[sizeof(struct in_addr)];
static uint32_t udp_port=17220;
static int priority = -1;
static uint8_t seq_num = 0;
static uint32_t udp_seq_num = 0;
static uint8_t use_tscf = 0;
static uint8_t use_udp = 0;

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
    case ARGPARSE_OPTION_MSG:
        strncpy(message_string, arg, MAX_MSG_SIZE);
        break;
    }

    return 0;
}

static struct argp_option options[] = {
    {"tscf", 't', 0, 0, "Use TSCF"},
    {"udp", 'u', 0, 0, "Use UDP" },
    {"message", ARGPARSE_OPTION_MSG, "MSG_STR", 0, "String message to send over IEEE 1722"},
    {"ifname", 'i', "IFNAME", 0, "Network interface (If Ethernet)"},
    {"dst-addr", 'd', "MACADDR", 0, "Stream destination MAC address (If Ethernet)"},
    {"dst-nw-addr", 'n', "NW_ADDR", 0, "Stream destination network address and port (If UDP)"},
    { 0 }
};

static struct argp argp = { options, parser, 0, 0};

static int init_cf_pdu(uint8_t* pdu)
{
    int res;
    if (use_tscf) {
        Avtp_Tscf_t* tscf_pdu = (Avtp_Tscf_t*) pdu;
        memset(tscf_pdu, 0, AVTP_TSCF_HEADER_LEN);
        Avtp_Tscf_Init(tscf_pdu);
        Avtp_Tscf_DisableTu(tscf_pdu);
        Avtp_Tscf_SetSequenceNum(tscf_pdu, seq_num++);
        Avtp_Tscf_SetStreamId(tscf_pdu, STREAM_ID);
        res = AVTP_TSCF_HEADER_LEN;
    } else {
        Avtp_Ntscf_t* ntscf_pdu = (Avtp_Ntscf_t*) pdu;
        memset(ntscf_pdu, 0, AVTP_NTSCF_HEADER_LEN);
        Avtp_Ntscf_Init(ntscf_pdu);
        Avtp_Ntscf_SetSequenceNum(ntscf_pdu, seq_num++);
        Avtp_Ntscf_SetStreamId(ntscf_pdu, STREAM_ID);
        res = AVTP_NTSCF_HEADER_LEN;
    }
    return res;
}

static int update_pdu_length(uint8_t* pdu, uint64_t length)
{
    if (use_tscf) {
        uint64_t payloadLen = length - AVTP_TSCF_HEADER_LEN;
        Avtp_Tscf_SetStreamDataLength((Avtp_Tscf_t*)pdu, payloadLen);
    } else {
        uint64_t payloadLen = length - AVTP_NTSCF_HEADER_LEN;
        Avtp_Ntscf_SetNtscfDataLength((Avtp_Ntscf_t*)pdu, payloadLen);

    }
    return 0;
}

static int prepare_acf_packet(uint8_t* acf_pdu, uint64_t gpc_code,
                          uint8_t* payload, uint16_t length) {

    Avtp_Gpc_t* pdu = (Avtp_Gpc_t*) acf_pdu;

    // Clear bits
    memset(pdu, 0, AVTP_GPC_HEADER_LEN);
    uint8_t acf_length = (AVTP_GPC_HEADER_LEN + ++length)/4;
    if (length % 4) acf_length++;

    // Prepare ACF PDU for CAN
    Avtp_Gpc_Init(pdu);
    Avtp_Gpc_SetGpcMsgId(pdu, gpc_code);
    Avtp_Gpc_SetAcfMsgLength(pdu, acf_length);
    memcpy(acf_pdu+AVTP_GPC_HEADER_LEN, payload, length);
    memset(acf_pdu+AVTP_GPC_HEADER_LEN+length, 0, acf_length*4 - length);

    return acf_length*4;
}

static int update_cf_length(uint8_t* cf_pdu, uint64_t length)
{
    if (use_tscf) {
        uint64_t payloadLen = length - AVTP_TSCF_HEADER_LEN;
        Avtp_Tscf_SetStreamDataLength((Avtp_Tscf_t*)cf_pdu, payloadLen);
    } else {
        uint64_t payloadLen = length - AVTP_NTSCF_HEADER_LEN;
        Avtp_Ntscf_SetNtscfDataLength((Avtp_Ntscf_t*)cf_pdu, payloadLen);

    }
    return 0;
}

int main(int argc, char *argv[])
{

    int fd, res;
    struct sockaddr_ll sk_ll_addr;
    struct sockaddr_in sk_udp_addr;
    uint8_t pdu[MAX_PDU_SIZE];
    uint16_t pdu_length, cf_length;
    uint64_t gpc_code = 0;

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

    // Sending loop
    for(;;) {

        // Pack into control formats
        uint8_t *cf_pdu;
        pdu_length = 0;
        cf_length = 0;

        // Usage of UDP means the PDU needs an encapsulation number
        if (use_udp) {
            Avtp_Udp_t *udp_pdu = (Avtp_Udp_t *) pdu;
            Avtp_Udp_SetEncapsulationSeqNo(udp_pdu, udp_seq_num++);
            pdu_length +=  sizeof(Avtp_Udp_t);
        }

        // Create the CF packet first
        cf_pdu = pdu + pdu_length;
        res = init_cf_pdu(cf_pdu);
        if (res < 0)
            goto err;
        pdu_length += res;
        cf_length += res;

        // Creation of the ACF Packet
        uint8_t* acf_pdu = pdu + pdu_length;
        res = prepare_acf_packet(acf_pdu, gpc_code++, (uint8_t*)message_string,
                                 strlen((char *)message_string));
        if (res < 0) goto err;
        pdu_length += res;
        cf_length += res;

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
        sleep(1);
    }

err:
    close(fd);
    return 1;

}